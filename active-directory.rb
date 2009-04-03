require 'rubygems'
require 'net/ldap'

module ActiveDirectory
  class Container
    attr_reader :name, :directory, :users, :groups
    attr :removed, true
    
    def initialize(name, directory)
      @name = name.gsub(/\s+/, "")
      @directory = directory
      # The removed flag must be set to true first since we are not in the
      # directory yet.
      @removed = true
      @directory.add_container self
      @removed = false
      @users = []
      @groups = []
    end
    
    # This is to add users who were previously removed and have their removed
    # flag set.
    def add_user(user)
      if user.removed
        if self == user.container
          # Someone could have manaually set the removed flag as well, so
          # we still check.
          @users.push user unless @users.include? user
          @directory.uids.push user.uid if user.instance_of? UNIXUser
          user.removed = false
        else
          raise "User must be in this container."
        end
      end
    end
    
    def remove_user(user)
      @users.delete user
      @directory.uids.delete user.uid if user.instance_of? UNIXUser
      user.removed = true
    end
    
    # This is to add groups who were previously removed and have their removed
    # flag set.
    def add_group(group)
      if group.removed
        if self == group.container
          # Someone could have manaually set the removed flag as well, so
          # we still check.
          @groups.push group unless @groups.include? group
          @directory.gids.push group.gid if group.instance_of? UNIXGroup
          group.removed = false
        else
          raise "Group must be in this container."
        end
      end
    end
    
    def remove_group(group)
      @groups.delete group
      @directory.gids.delete group.gid if group.instance_of? UNIXGroup
      group.removed = true
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
      "Container [#{@name},#{@directory.root}]"
    end
  end
  
  class User
    attr_reader :username, :container, :distinguished_name, :groups
    attr :full_name, true
    attr :password, true
    attr :removed, true
    
    def initialize(username, container)
      @username = username
      @common_name = username
      @container = container
      @distinguished_name = "cn=" + @common_name + "," + @container.name +
                            "," + @container.directory.root
      @groups = []
      # A UNIXUser adding itself the container needs to happen at the end of
      # the initializer in that class instead because the UID value is needed.
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_user self unless self.instance_of? UNIXUser
      @removed = false
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
                            @container.directory.root
      @common_name = cn
    end
    
    def add_group(group)
      if @container.directory == group.container.directory
        @groups.push group unless @groups.include? group
        group.add_user self unless group.users.include? self
      else
        raise "Group must be in the same directory."
      end
    end
    
    def remove_group(group)
      @groups.delete group
      group.remove_user self if group.users.include? self
    end
    
    def member_of?(group)
      @groups.include? group
    end
    
    def ==(other)
      # The disginguished name and the username (sAMAccountName) must be
      # unique (case-insensitive).
      if @container.directory == other.container.directory
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
    
    def initialize(username, container, uid, main_group, shell, home_directory,
                   nis_domain = nil)
      if container.directory.uids.include? uid
        raise "UID is already in use in the directory."
      end
      
      super username, container
      @uid = uid
      @main_group = main_group
      
      if @container.directory == @main_group.container.directory
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
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_user self
      @removed = false
    end
    
    def add_group(group)
      if group.instance_of? UNIXGroup
        if @container.directory == group.container.directory
          unless @groups.include?(group) || group == @main_group
            @groups.push group
            group.add_user self
          end
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
    attr_reader :name, :container, :distinguished_name, :users, :groups
    attr :removed, true
    
    def initialize(name, container)
      @name = name
      @container = container
      @distinguished_name = "cn=" + name + "," + @container.name + "," +
                            @container.directory.root
      @users = []
      @groups = []
      # A UNIXGroup adding itself the container needs to happen at the end of
      # the initializer in that class instead because the GID value is needed.
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_group self unless self.instance_of? UNIXGroup
      @removed = false
    end
    
    def add_user(user)
      if @container.directory == user.container.directory
        @users.push user unless @users.include? user
        user.add_group self unless user.groups.include? self
      else
        raise "User must be in the same directory."
      end
    end
    
    def remove_user(user)
      @users.delete user
      user.remove_group self if user.groups.include? self
    end
    
    def member_of?(group)
      @groups.include? group
    end
    
    def add_group(group)
      unless @container.directory == group.container.directory
        raise "Group must be in the same directory."
      end
      
      if self == group
        raise "A group cannot have itself as a member."
      end
      
      @groups.push group unless @groups.include? group
    end
    
    def remove_group(group)
      @groups.delete group
    end
    
    def ==(other)
      # I believe that it is not possible to have a distinguished name that's
      # not built from the name itself, but just in case, I am checking both.
      # The disginguished name and the group name (like a user) must be unique
      # (case-insensitive).
      if @container.directory == other.container.directory
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
    
    def initialize(name, container, gid, nis_domain = nil)
      if container.directory.gids.include? gid
        raise "GID is already in use in the directory."
      end
      
      super name, container
      @gid = gid
      @nis_domain = nis_domain
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_group self
      @removed = false
    end
    
    def add_user(user)
      if user.instance_of?(UNIXUser) && self == user.main_group
          raise "Cannot add a user to the user's main UNIXGroup."
      else
        super user
      end
    end
    
    def to_s
      "UNIXGroup [(GID #{@gid}) #{@distinguished_name}]"
    end
  end
  
  class AD
    attr_reader :root, :domain, :server, :port, :ldap
    attr :uids, true
    attr :gids, true
    attr :containers, true
    
    def initialize(root, password, user = "cn=Administrator,cn=Users",
                   server = "localhost", port = 389)
      @root = root.gsub(/\s+/, "")
      @domain = @root.gsub(/dc=/, "").gsub(/,/, ".")
      @password = password
      @user = user
      @server = server
      @port = port
      @containers = []
      @uids = []
      @gids = []
      @ldap = Net::LDAP.new :host => @server,
                            :port => @port,
                            :auth => {
                                  :method => :simple,
                                  :username => @user + "," + @root,
                                  :password => @password
                            }
    end
    
    # This is to add containers who were previously removed and have their
    # removed flag set.
    def add_container(container)
      if container.removed
        if self == container.directory
          # Someone could have manaually set the removed flag as well, so
          # we still check.
          @containers.push container unless @containers.include? container
          container.removed = false
        else
          raise "Container must be in the same directory."
        end
      end
    end
    
    def remove_container(container)
      @containers.delete container
      container.removed = true
    end
    
    # Users are only stored in containers, which are only stored here.
    def find_user(username)
      @containers.each do |container|
        found = container.users.find do |user|
          # This relies on the fact that usernames must be unique in an AD.
          user.username == username
        end
        
        return found if found
      end
    end
    
    # Groups are only stored in containers, which are only stored here.
    def find_group(name)
      @containers.each do |container|
        found = container.groups.find do |group|
          # This relies on the fact that group names must be unique in an AD.
          group.name == name
        end
        
        return found if found
      end
    end
    
    def find_group_by_gid(gid)
      @containers.each do |container|
        found = container.groups.find do |group|
          group.gid == gid if group.instance_of? UNIXGroup
        end
        
        return found if found
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
          
          # Note that groups add themselves to their container.
          if gid
            UNIXGroup.new(entry.name.pop, self, container, gid, nis_domain)
          else
            Group.new(entry.name.pop, self, container)
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
          
          # Note that users add themselves to their container.
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
        end
      end
      
      # TO DO: add users to the groups they should be in, this will
      # automatically add the groups to the users as well. This could be
      # done in reverse - whatever, just do it.
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
