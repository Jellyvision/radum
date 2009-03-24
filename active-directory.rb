require 'rubygems'
require 'net/ldap'

module ActiveDirectory
  class Container
    attr_reader :name, :directory, :users, :groups
    
    def initialize(name, directory)
      @name = name.gsub(/\s+/, "")
      @directory = directory
      @users = []
      @groups = []
    end
    
    def add_user(user)
      if self == user.container
        @users.push user unless @users.include? user
      else
        raise "User must be in this container."
      end
    end
    
    def add_group(group)
      if self == group.container
        @groups.push group unless @groups.include? group
      else
        raise "Group must be in this container."
      end
    end
    
    def ==(other)
      if @directory == other.directory
        @name.downcase == other.name.downcase
      else
        false
      end
    end
    
    def eql?(other)
      self == other
    end
    
    def to_s
      "Container [#{@name}]"
    end
  end
  
  class User
    attr_reader :username, :directory, :container, :distinguished_name, :groups
    attr :full_name, true
    attr :password, true
    
    def initialize(username, directory, container)
      @username = username
      @common_name = username
      @directory = directory
      
      if @directory == container.directory
        @container = container
      else
        raise "Container must be in the same directory."
      end
      
      @distinguished_name = "cn=" + @common_name + "," + @container.name +
                            "," + directory.root
      @groups = []
      @container.add_user self
    end
    
    def add_group(group)
      if @directory == group.directory
        @groups.push group unless @groups.include? group
      else
        raise "Group must be in the same directory."
      end
    end
    
    def remove_group(group)
      @groups.delete group
    end
    
    def common_name
      @common_name
    end
    
    # The @common_name is set to @username by default. The @username value
    # corresponds to the sAMAccountName attribute. It is possible for the cn
    # to be different than sAMAccountName however, so this allows one to set
    # @common_name directly. Setting the @common_name also changes the
    # @distinguished_name accordingly (which is also built automatically).
    def common_name=(cn)
      @distinguished_name = "cn=" + cn + "," + @container.name + "," +
                            directory.root
      @common_name = cn
    end
    
    def ==(other)
      # The disginguished name and the username (sAMAccountName) must be
      # unique (case-insensitive).
      if @directory == other.directory
        @distinguished_name.downcase == other.distinguished_name.downcase ||
        @username.downcase == other.username.downcase
      else
        false
      end
    end
    
    def eql?(other)
      self == other
    end
    
    def to_s
      "User [#{@username} #{@distinguished_name}]"
    end
  end
  
  class UNIXUser < User
    attr_reader :uid, :main_group, :gid, :shell, :home_directory, :nis_domain
    attr :gecos, true
    
    def initialize(username, directory, container, uid, main_group, shell,
                   home_directory, nis_domain = nil)
      super username, directory, container
      @uid = uid
      @main_group = main_group
      
      if @directory == @main_group.directory
        unless @main_group.instance_of? UNIXGroup
          raise "UNIXUser main_group must be a UNIXGroup."
        else
          @gid = @main_group.gid
        end
      else
        raise "UNIXUser main_group must be in the same directory."
      end
      
      @shell = shell
      @home_directory = home_directory
      @nis_domain = nis_domain
    end
    
    def add_group(group)
      if group.instance_of? UNIXGroup
        if @directory == group.directory
          @groups.push group unless(@groups.include?(group) ||
                                    group == @main_group)
        else
          raise "Group must be in the same directory."
        end
      else
        super group
      end
    end
    
    def to_s
      "UNIXUser [(UID #{@uid}, GID #{@main_group.gid}) #{@username} " +
      "#{@distinguished_name}]"
    end
  end
  
  class Group
    attr_reader :name, :directory, :container, :distinguished_name
    
    def initialize(name, directory, container)
      @name = name
      @directory = directory
      
      if @directory == container.directory
        @container = container
      else
        raise "Container must be in the same directory."
      end
      
      @distinguished_name = "cn=" + name + "," + @container.name + "," +
                            directory.root
      @container.add_group self
    end
    
    def ==(other)
      # I believe that it is not possible to have a distinguished name that's
      # not built from the name itself, but just in case, I am checking both.
      # The disginguished name and the group name (like a user) must be unique
      # (case-insensitive).
      if @directory == other.directory
        @distinguished_name.downcase == other.distinguished_name.downcase ||
        @name.downcase == other.name.downcase
      else
        false
      end
    end
    
    def eql?(other)
      self == other
    end
    
    def to_s
      "Group [#{@distinguished_name}]"
    end
  end
  
  class UNIXGroup < Group
    attr_reader :gid, :nis_domain
    
    def initialize(name, directory, container, gid, nis_domain = nil)
      super name, directory, container
      @gid = gid
      @nis_domain = nis_domain
    end
    
    def to_s
      "UNIXGroup [(GID #{@gid}) #{@distinguished_name}]"
    end
  end
  
  class AD
    attr_reader :root, :domain, :server, :port, :ldap
    attr :containers, true
    attr :users, true
    attr :groups, true
    
    def initialize(root, password, user = "cn=Administrator,cn=Users",
                   server = "localhost", port = 389)
      @root = root.gsub(/\s+/, "")
      @domain = @root.gsub(/dc=/, "").gsub(/,/, ".")
      @password = password
      @user = user
      @server = server
      @port = port
      @containers = []
      @users = []
      @groups = []
      @ldap = Net::LDAP.new :host => @server,
                            :port => @port,
                            :auth => {
                                  :method => :simple,
                                  :username => @user + "," + @root,
                                  :password => @password
                            }
    end
    
    def add_container(container)
      if self == container.directory
        @containers.push container unless @containers.include? container
      else
        raise "Container must be in the same directory."
      end
    end
    
    def remove_container(container)
      @containers.delete conainer
    end
    
    def add_user(user)
      found = @containers.find do |container|
        user.container == container
      end
      
      raise "User must be in a container for this directory." unless found
      
      # There is no need to check if the user is in the same directory if the
      # container check above was successful, and that's the only way we can
      # get here.
      @users.push user unless @users.include? user
    end
    
    def remove_user(user)
      @users.delete user
    end
    
    def find_user(username, container)
      @users.find do |user|
        user.username == username && user.container == container
      end
    end
    
    def add_group(group)
      found = @containers.find do |container|
        group.container == container
      end
      
      raise "Group must be in a container for this directory." unless found
      
      # There is no need to check if the group is in the same directory if the
      # container check above was successful, and that's the only way we can
      # get here.
      @groups.push group unless @groups.include? group
    end
    
    def remove_group(group)
      @groups.delete group
    end
    
    def find_group(name, container)
      @groups.find do |group|
        group.name == name && group.container == container
      end
    end
    
    def find_group_by_gid(gid)
      @groups.find do |group|
        group.gid == gid if group.instance_of? UNIXGroup
      end
    end
    
    def load
      # Find all the groups first. We might need one to represent the main
      # group of a UNIX user.
      filter = Net::LDAP::Filter.eq("objectclass", "group")
      
      @containers.each do |container|
        base = container.name + ",#{@root}"
        
        @ldap.search(:base => base, :filter => filter) do |entry|
          gid = nil
          nis_domain = nil
          
          begin
            gid = entry.gidNumber.pop.to_i
            nis_domain = entry.msSFU30NisDomain.pop
          rescue NoMethodError
          end
          
          if gid
            add_group(UNIXGroup.new(entry.name.pop, self, container,
                                    gid, nis_domain))
          else
            add_group(Group.new(entry.name.pop, self, container))
          end 
        end
      end
      
      # Find all the users. The main UNIX group must be set for UNIXUser
      # objects, so it will be necessary to search for that.
      filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @containers.each do |container|
        base = container.name + ",#{@root}"
        
        @ldap.search(:base => base, :filter => filter) do |entry|
          uid = nil
          gid = nil
          nis_domain = nil
          
          begin
            uid = entry.uidNumber.pop.to_i
            gid = entry.gidNumber.pop.to_i
            nis_domain = entry.msSFU30NisDomain.pop
          rescue NoMethodError
          end
          
          if uid && gid
            if group = find_group_by_gid(gid)
              user = UNIXUser.new(entry.sAMAccountName.pop, self, container,
                                  uid, group, entry.loginShell.pop,
                                  entry.unixHomeDirectory.pop, nis_domain)
              user.common_name = entry.cn.pop
            end
          else
            user = User.new(entry.sAMAccountName.pop, self, container)
            user.common_name = entry.cn.pop
          end
          
          add_user(user)
        end
      end
    end
    
    def ==(other)
      @root.downcase == other.root.downcase
    end
    
    def eql?(other)
      self == other
    end
    
    def to_s
      "AD [#{@root} #{@server} #{@port}]"
    end
  end
end
