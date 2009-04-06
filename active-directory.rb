require 'rubygems'
require 'net/ldap'

module ActiveDirectory
  class Container
    attr_reader :name, :directory, :users, :groups
    attr :removed, true
    
    def initialize(name, directory)
      name.gsub!(/\s+/, "")
      
      # The container name (like a user) must be unique (case-insensitive).
      # We would not want someone accidently making two equal containers
      # and adding users/groups in the wrong way.
      if directory.find_container name
        raise "Container is already in the directory."
      end
      
      @name = name
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
          unless @users.include? user
            @users.push user
            @directory.rids.push user.rid if user.rid
            @directory.uids.push user.uid if user.instance_of? UNIXUser
          end
          
          user.removed = false
        else
          raise "User must be in this container."
        end
      end
    end
    
    def remove_user(user)
      @users.delete user
      @directory.rids.delete user.rid if user.rid
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
          unless @groups.include? group
            @groups.push group
            @directory.rids.push group.rid if group.rid
            @directory.gids.push group.gid if group.instance_of? UNIXGroup
          end
          
          group.removed = false
        else
          raise "Group must be in this container."
        end
      end
    end
    
    def remove_group(group)
      @groups.delete group
      @directory.rids.delete group.rid if group.rid
      @directory.gids.delete group.gid if group.instance_of? UNIXGroup
      group.removed = true
    end
    
    def to_s
      "Container [#{@name},#{@directory.root}]"
    end
  end
  
  class User
    attr_reader :username, :container, :rid, :distinguished_name, :groups
    attr :full_name, true
    attr :password, true
    attr :removed, true
    
    def initialize(username, container, rid = nil)
      # The RID must be unique.
      if container.directory.rids.include? rid
        raise "RID is already in use in the directory."
      end
      
      # The username (sAMAccountName) must be unique (case-insensitive). This
      # is needed in case someone tries to make the same username in two
      # different containers.
      if container.directory.find_user username
        raise "User is already in the directory."
      end
      
      @username = username
      @common_name = username
      @container = container
      @rid = rid
      @distinguished_name = "cn=" + @common_name + "," + @container.name +
                            "," + @container.directory.root
      @groups = []
      # A UNIXUser adding itself the container needs to happen at the end of
      # the initializer in that class instead because the UID value is needed.
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_user self unless instance_of? UNIXUser
      @removed = false
    end
    
    def primary_group
      @primary_group
    end
    
    def primary_group=(group)
      remove_group group
      @primary_group = group
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
      @groups.include? group || @primary_group == group
    end
    
    def to_s
      "User [(RID #{@rid}) #{@username} #{@distinguished_name}]"
    end
  end
  
  class UNIXUser < User
    attr_reader :uid, :main_group, :gid, :shell, :home_directory, :nis_domain
    attr :gecos, true
    
    def initialize(username, container, uid, main_group, shell, home_directory,
                   nis_domain = nil, rid = nil)
      # The UID must be unique.
      if container.directory.uids.include? uid
        raise "UID is already in use in the directory."
      end
      
      super username, container, rid
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
      "UNIXUser [(RID #{@rid}, UID #{@uid}, GID #{@main_group.gid}) " +
      "#{@username} " + "#{@distinguished_name}]"
    end
  end
  
  class Group
    attr_reader :name, :container, :rid, :distinguished_name, :users, :groups
    attr :removed, true
    
    def initialize(name, container, rid = nil)
      # The RID must be unique.
      if container.directory.rids.include? rid
        raise "RID is already in use in the directory."
      end
      
      # The group name (like a user) must be unique (case-insensitive). This
      # is needed in case someone tries to make the same group name in two
      # different containers.
      if container.directory.find_group name
        raise "Group is already in the directory."
      end
      
      @name = name
      @container = container
      @rid = rid
      @distinguished_name = "cn=" + name + "," + @container.name + "," +
                            @container.directory.root
      @users = []
      @groups = []
      # A UNIXGroup adding itself the container needs to happen at the end of
      # the initializer in that class instead because the GID value is needed.
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_group self unless instance_of? UNIXGroup
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
    
    def to_s
      "Group [(RID #{@rid}) #{@distinguished_name}]"
    end
  end
  
  class UNIXGroup < Group
    attr_reader :gid, :nis_domain
    
    def initialize(name, container, gid, nis_domain = nil, rid = nil)
      # The GID must be unique.
      if container.directory.gids.include? gid
        raise "GID is already in use in the directory."
      end
      
      super name, container, rid
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
      "UNIXGroup [(RID #{@rid}, GID #{@gid}) #{@distinguished_name}]"
    end
  end
  
  class AD
    attr_reader :root, :domain, :server, :port, :ldap
    attr :uids, true
    attr :gids, true
    attr :rids, true
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
      # RIDs are in a flat namespace, so there's no need to keep track of them
      # for user or group objects specifically, just in the directory overall.
      @rids = []
      @ldap = Net::LDAP.new :host => @server,
                            :port => @port,
                            :auth => {
                                  :method => :simple,
                                  :username => @user + "," + @root,
                                  :password => @password
                            }
    end
    
    def find_container(name)
      @containers.find do |container|
        # This relies on the fact that a container name must be unique in a
        # directory.
        container.name.downcase == name.downcase
      end
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
          # This relies on the fact that usernames (sAMAccountName) must be
          # unique in a directory.
          user.username.downcase == username.downcase
        end
        
        return found if found
      end
      
      return false
    end
    
    # Groups are only stored in containers, which are only stored here.
    def find_group(name)
      @containers.each do |container|
        found = container.groups.find do |group|
          # This relies on the fact that group names must be unique in a
          # directory.
          group.name.downcase == name.downcase
        end
        
        return found if found
      end
      
      return false
    end
    
    def find_group_by_rid(rid)
      @containers.each do |container|
        found = container.groups.find do |group|
          group.rid == rid
        end
        
        return found if found
      end
      
      return false
    end
    
    def find_group_by_gid(gid)
      @containers.each do |container|
        found = container.groups.find do |group|
          group.gid == gid if group.instance_of? UNIXGroup
        end
        
        return found if found
      end
      
      return false
    end
    
    def load
      # Find all the groups first. We might need one to represent the main
      # group of a UNIX user.
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
      
      @containers.each do |container|
        base = container.name + ",#{@root}"
        
        @ldap.search(:base => base, :filter => group_filter) do |entry|
          gid = nil
          nis_domain = nil
          
          begin
            gid = entry.gidNumber.pop.to_i
            nis_domain = entry.msSFU30NisDomain.pop
          rescue NoMethodError
          end
          
          rid = sid2rid_int(entry.objectSid.pop)
          
          # Note that groups add themselves to their container.
          if gid
            UNIXGroup.new(entry.name.pop, container, gid, nis_domain, rid)
          else
            Group.new(entry.name.pop, container, rid)
          end 
        end
      end
      
      # Find all the users. The main UNIX group must be set for UNIXUser
      # objects, so it will be necessary to search for that.
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @containers.each do |container|
        base = container.name + ",#{@root}"
        
        @ldap.search(:base => base, :filter => user_filter) do |entry|
          uid = nil
          gid = nil
          nis_domain = nil
          
          begin
            uid = entry.uidNumber.pop.to_i
            gid = entry.gidNumber.pop.to_i
            nis_domain = entry.msSFU30NisDomain.pop
          rescue NoMethodError
          end
          
          rid = sid2rid_int(entry.objectSid.pop)
          
          # Note that users add themselves to their container.
          if uid && gid
            if group = find_group_by_gid(gid)
              user = UNIXUser.new(entry.sAMAccountName.pop, container, uid,
                                  group, entry.loginShell.pop,
                                  entry.unixHomeDirectory.pop, nis_domain,
                                  rid)
              user.common_name = entry.cn.pop
            end
          else
            user = User.new(entry.sAMAccountName.pop, container, rid)
            user.common_name = entry.cn.pop
          end
        end
      end
      
      # Add users to groups, which also adds the groups to the user, etc. This
      # takes into account a UNIXUser's main_group. In that case, the main_group
      # attribute is set instead of adding the group the the UNIXUser's group
      # array.
      @containers.each do |container|
        container.groups.each do |group|
          base = "cn=#{group.name}," + container.name + ",#{@root}"
          
          @ldap.search(:base => base, :filter => group_filter) do |entry|
            begin
              entry.member.each do |member|
                name = member.split(',')[0].split('=')[1]
                # Groups can have groups or users as members, unlike UNIX where
                # groups cannot contain group members.
                member_group = find_group name
                
                if member_group
                  group.add_group member_group
                end
                
                member_user = find_user name
                
                if member_user
                  if member_user.instance_of? UNIXUser
                    unless group == member_user.main_group
                      group.add_user member_user
                    end
                  else
                    group.add_user member_user
                  end
                end
              end
            rescue NoMethodError
            end
          end
        end
        
        # The "members" AD attribute for a group does not contain users in
        # its list if their "primaryGroupID" attribute defines that membership
        # instead. For example, the "Domain Users" group contains all accounts
        # as members usually, but normally its "members" attribute is empty
        # because those users have their membership defined by their own
        # "primaryGroupID" instead (which is the RID of "Domain Users" most
        # of the time). Therefore, we need to set the User instance's
        # primary_group attribute to get the real picture.
        container.users.each do |user|
          base = "cn=#{user.common_name}," + container.name + ",#{@root}"
          
          @ldap.search(:base => base, :filter => user_filter) do |entry|
            rid = entry.primaryGroupID.pop.to_i
            primary_group = find_group_by_rid rid
            
            if primary_group
              user.primary_group = primary_group
            else
              raise "User should have primary group in directory."
            end
          end
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
    
    private
    
    def sid2rid_int(sid)
      sid.unpack("H2H2nNV*").pop.to_i
    end
  end
end
