# The RADUM module provides an interface to Microsoft Active Directory for
# working with users and groups. The User class represents a standard Windows
# user account. The UNIXUser class represents a Windows account that has UNIX
# attributes. Similarly, the Group class represents a standard Windows group,
# and a UNIXGroup represents a Windows group that has UNIX attributes. This
# module concentrates only on users and groups at this time.
#
# This is a pure Ruby implementation, but when possible it utilizes the
# Windows command line to create users and groups as needed. On UNIX systems
# these methods will fail by returning nil. Methods that fall under this
# restriction are noted.
#
# Author:: Shaun Rowland <mailto:rowand@shaunrowland.com>
# Copyright:: Copyright 2009 Shaun Rowland. All rights reserved.
# License:: BSD License included in the project LICENSE file.

module RADUM
  # Group type constants.
  #
  # These are the Fixnum representation of what should be Bignum objects in
  # some cases as far as I am aware. In the AD Users and Groups tool, they are
  # shown as hexidecimal values, indicating they should be Bignums (well, some
  # of them obviously). However, if you try to edit the values in that tool
  # (with advanced attribute editing enabled or with the ADSI Edit tool) these
  # show up as the Fixnum values here. We are going to stick with that, even
  # though it is lame. I could not pull these out as Bignum objects. Some
  # of these are small enough to be Fixnums though, so I left them as their
  # hexidecimal values. These values correspond to the LDAP groupType attribute
  # for group objects.
  GROUP_DOMAIN_LOCAL_SECURITY = -2147483644
  GROUP_DOMAIN_LOCAL_DISTRIBUTION = 0x4
  GROUP_GLOBAL_SECURITY = -2147483646
  GROUP_GLOBAL_DISTRIBUTION = 0x2
  GROUP_UNIVERSAL_SECURITY = -2147483640
  GROUP_UNIVERSAL_DISTRIBUTION = 0x8
  
  # Some useful constants from lmaccess.h for use with creating user accounts.
  UF_ACCOUNTDISABLE = 0x0002;
  UF_PASSWD_NOTREQD = 0x0020;
  UF_PASSWD_CANT_CHANGE = 0x0040;
  UF_NORMAL_ACCOUNT = 0x0200;
  # I don't think these are working - I am sure the last one doesn't work.
  #UF_DONT_EXPIRE_PASSWD = 0x10000;
  #UF_PASSWORD_EXPIRED = 0x800000;
  
  # This is a convenience method to return a String representation of a
  # Group or UNIXGroup object's type attribute, which has the value of one of
  # the RADUM group type constants.
  def RADUM.group_type_to_s(type)
    case type
    when GROUP_DOMAIN_LOCAL_SECURITY
      "GROUP_DOMAIN_LOCAL_SECURITY"
    when GROUP_DOMAIN_LOCAL_DISTRIBUTION
      "GROUP_DOMAIN_LOCAL_DISTRIBUTION"
    when GROUP_GLOBAL_SECURITY
      "GROUP_GLOBAL_SECURITY"
    when GROUP_GLOBAL_DISTRIBUTION
      "GROUP_GLOBAL_DISTRIBUTION"
    when GROUP_UNIVERSAL_SECURITY
      "GROUP_UNIVERSAL_SECURITY"
    when GROUP_UNIVERSAL_DISTRIBUTION
      "GROUP_UNIVERSAL_DISTRIBUTION"
    else "UNKNOWN"
    end
  end
  
  # The AD class represents the Active Directory. All opeartions that involve
  # communication between the User, UNIXUser, Group, and UNIXGroup classes are
  # handled by the AD object. The AD object should be the first object created,
  # generally followed by Container objects. The Container object requires an
  # AD object. All other objects require a Container object. Generally, methods
  # prefixed with "load_" pull data out of the Active Directory and methods
  # prefixed with "sync_" push data to the Active Directory as required.
  class AD
    # The root of the Active Directory. This is a String representing an LDAP
    # path, such as "dc=example,dc=com".
    attr_reader :root
    # The domain name of the Active Directory. This is calculated from the root
    # attribute.
    attr_reader :domain
    # The Active Directory user used to connect to the Active Directory. This
    # is specified using an LDAP path to the user account, without the root
    # component, such as "cn=Administrator,cn=Users". This defaults to
    # "cn=Administrator,cn=Users" when an AD is created using AD.new.
    attr_reader :user
    # The server hostname or IP address of the Active Directory server. This
    # defaults to "localhost" when an AD is created using AD.new.
    attr_reader :server
    # The array of UID values from UNIXUser objects in the AD object. This is
    # automatically managed by the other objects and should not be modified
    # directly.
    attr_accessor :uids
    # The array of GID values from UNIXGroup objects in the AD object. This is
    # automatically managed by the other objects and should not be modified
    # directly.
    attr_accessor :gids
    # The array of RID values for User, UNIXUser, Group, and UNIXGroup objects
    # in the AD object. This is automatically managed by the other objects and
    # should not be modified directly.
    attr_accessor :rids
    # The array of Containers in the AD object. This is automatically managed
    # by the Container and AD objects and should not be modified directly
    # except for using the methods of those classes.
    attr_accessor :containers
    
    # Create a new AD object to represent an Active Directory environment.
    # The root is a String representation of an LDAP path, such as
    # "dc=example,dc=com". The password is used in conjunction with the
    # specified user, which defaults to Administrator
    # ("cn=Administrator,cn=Users"), to authenticate when a connection is
    # is actually utilized in data processing ("load_" and "sync_" prefixed
    # methods). The server is a String representing either the hostname or IP
    # address of the Active Directory server, which defaults to "localhost".
    # This module requires TLS to create user accounts in Active Directory
    # properly, so you will need to make sure you have a certificate server
    # so that you can connect with SSL on port 636.
    #
    #   ad = RADUM::AD.new('dc=example,dc=com', 'password',
    #                      'cn=Administrator,cn=Users', '192.168.1.1')
    #
    # A Container object for "cn=Users" is automatically created and added to
    # the AD when an AD object is created. This is meant to be a convenience
    # because most (if not all) User and UNIXUser objects will have the
    # "Domain Users" Windows group as their primary Windows group. It is
    # possible to remove this Container if absolutely necessary, but it should
    # not be an issue.
    def initialize(root, password, user = "cn=Administrator,cn=Users",
                   server = "localhost")
      @root = root.gsub(/\s+/, "")
      @domain = @root.gsub(/dc=/, "").gsub(/,/, ".")
      @password = password
      @user = user
      @server = server
      @containers = []
      @uids = []
      @gids = []
      # RIDs are in a flat namespace, so there's no need to keep track of them
      # for user or group objects specifically, just in the directory overall.
      @rids = []
      @port = 636

      @ldap = Net::LDAP.new :host => @server,
                            :port => @port,
                            :encryption => :simple_tls,
                            :auth => {
                                  :method => :simple,
                                  :username => @user + "," + @root,
                                  :password => @password
                            }
      
      # We add the cn=Users container by default because it is highly likely
      # that users have the Domain Users Windows group as their Windows
      # primary group. If we did not do this, there would likely be a ton
      # of warning messages in the load() method. Keep in mind that containers
      # automatically add themselves to their AD object.
      Container.new("cn=Users", self)
    end
    
    # The port number used to communicate with the Active Directory server.
    def port
      @port
    end
    
    # Set the port number used to communicate with the Active Directory server.
    # This defaults to 636 for TLS in order to create user accounts properly,
    # but can be set here for nonstandard configurations.
    def port=(port)
      @port = port
      @ldap.port = port
    end
    
    # Find a Container in the AD by name. The search is case-insensitive. The
    # Container is returned if found, otherwise nil is returned.
    def find_container(name)
      @containers.find do |container|
        # This relies on the fact that a container name must be unique in a
        # directory.
        container.name.downcase == name.downcase
      end
    end
    
    # Add Container objects which were previously removed and had their removed
    # attribute set. Containers automatically add themselves to their AD object,
    # so this is only needed when adding a removed Container object back into
    # the AD. A Container must have been a member of the AD in order to be
    # added back into it. If this is not true, a RuntimeError is raised. If
    # successful, the Container object's removed attribute is set to false.
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
    
    # Remove a Container from the AD. This sets the Container object's removed
    # attribute to true.
    def remove_container(container)
      @containers.delete container
      container.removed = true
    end
    
    # Returns an Array of all User and UNIXUser objects in all Containers
    # in the AD.
    def users
      all_users = []
      
      @containers.each do |container|
        container.users.each do |user|
          all_users.push user
        end
      end
      
      all_users
    end
    
    # Find a User or UNIXUser in the AD by username. The search is
    # case-insensitive. The User or UNIXUser is returned if found, otherwise
    # nil is returned.
    def find_user(username)
      @containers.each do |container|
        found = container.users.find do |user|
          # This relies on the fact that usernames (sAMAccountName) must be
          # unique in a directory.
          user.username.downcase == username.downcase
        end
        
        return found if found
      end
      
      return nil
    end
    
    # Find a User or UNIXUser in the AD by RID. The User or UNIXUser is
    # returned if found, otherwise nil is returned.
    def find_user_by_rid(rid)
      @containers.each do |container|
        found = container.users.find do |user|
          user.rid == rid
        end
        
        return found if found
      end
      
      return nil
    end
    
    # Find a UNIXUser in the AD by UID. The UNIXUser is returned if found,
    # otherwise nil is returned.
    def find_user_by_uid(uid)
      @containers.each do |container|
        found = container.users.find do |user|
          user.uid == uid if user.instance_of? UNIXUser
        end
        
        return found if found
      end
      
      return nil
    end
    
    # Returns an Array of all Group and UNIXGroup objects in all Containers
    # in the AD.
    def groups
      all_groups = []
      
      @containers.each do |container|
        container.groups.each do |group|
          all_groups.push group
        end
      end
      
      all_groups
    end
    
    # Find a Group or UNIXGroup in the AD by name. The search is
    # case-insensitive. The Group or UNIXGroup is returned if found, otherwise
    # nil is returned.
    def find_group(name)
      @containers.each do |container|
        found = container.groups.find do |group|
          # This relies on the fact that group names must be unique in a
          # directory.
          group.name.downcase == name.downcase
        end
        
        return found if found
      end
      
      return nil
    end
    
    # Find a Group or UNIXGroup in the AD by RID. The Group or UNIXGroup is
    # returned if found, otherwise nil is returned.
    def find_group_by_rid(rid)
      @containers.each do |container|
        found = container.groups.find do |group|
          group.rid == rid
        end
        
        return found if found
      end
      
      return nil
    end
    
    # Find a UNIXGroup in the AD by GID. The UNIXGroup is returned if found,
    # otherwise nil is returned.
    def find_group_by_gid(gid)
      @containers.each do |container|
        found = container.groups.find do |group|
          group.gid == gid if group.instance_of? UNIXGroup
        end
        
        return found if found
      end
      
      return nil
    end
    
    # Load all user and group objects in Active Directory that are in the AD
    # object's Containers. This automatically creates User, UNIXUser, Group,
    # and UNIXGroup objects as needed and sets all of their attributes
    # correctly. This can be used to initialize a program using the RADUM 
    # module for account management work.
    #
    # Users are not created if their primary Windows group is not found
    # during the load. UNIXUsers are not created if their main UNIX group
    # is not found during the load. Warning messages are printed in each
    # case. Make sure all required Containers are in the AD before loading
    # data from Active Directory to avoid this problem.
    def load
      # Find all the groups first. We might need one to represent the main
      # group of a UNIX user.
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
      
      @containers.each do |container|
        base = container.name + ",#{@root}"
        
        @ldap.search(:base => base, :filter => group_filter) do |entry|
          # These are attributes that might be empty. If they are empty,
          # a NoMethodError exception will be raised. We have to check each
          # individually and set an initial indicator value (nil). All the
          # other attributes should exist and do not require this level of
          # checking.
          gid = nil
          nis_domain = nil
          unix_password = nil
          
          begin
            gid = entry.gidNumber.pop.to_i
          rescue NoMethodError
          end
          
          begin
            nis_domain = entry.msSFU30NisDomain.pop
          rescue NoMethodError
          end
          
          begin
            unix_password = entry.unixUserPassword.pop
          rescue NoMethodError
          end
          
          rid = sid2rid_int(entry.objectSid.pop)
          
          # Note that groups add themselves to their container.
          if gid
            nis_domain = "radum" unless nis_domain
            group = UNIXGroup.new(entry.name.pop, container, gid,
                                  entry.groupType.pop.to_i, nis_domain, rid)
            group.unix_password = unix_password if unix_password
          else
            Group.new(entry.name.pop, container, entry.groupType.pop.to_i, rid)
          end 
        end
      end
      
      # Find all the users. The main UNIX group must be set for UNIXUser
      # objects, so it will be necessary to search for that.
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @containers.each do |container|
        base = container.name + ",#{@root}"
        
        @ldap.search(:base => base, :filter => user_filter) do |entry|
          # These are attributes that might be empty. If they are empty,
          # a NoMethodError exception will be raised. We have to check each
          # individually and set an initial indicator value (nil). All the
          # other attributes should exist and do not require this level of
          # checking.
          first_name = nil
          middle_name = nil
          surname = nil
          uid = nil
          gid = nil
          nis_domain = nil
          gecos = nil
          unix_password = nil
          shadow_expire = nil
          shadow_flag = nil
          shadow_inactive = nil
          shadow_last_change = nil
          shadow_max = nil
          shadow_min = nil
          shadow_warning = nil
          
          begin
            first_name = entry.givenName.pop
          rescue NoMethodError
          end
          
          begin
            middle_name = entry.middleName.pop
          rescue NoMethodError
          end
          
          begin
            surname = entry.sn.pop
          rescue NoMethodError
          end
          
          begin
            uid = entry.uidNumber.pop.to_i
          rescue NoMethodError
          end

          begin
            gid = entry.gidNumber.pop.to_i
          rescue NoMethodError
          end
          
          begin
            nis_domain = entry.msSFU30NisDomain.pop
          rescue NoMethodError
          end
          
          begin
            gecos = entry.gecos.pop
          rescue NoMethodError
          end
          
          begin
            unix_password = entry.unixUserPassword.pop
          rescue NoMethodError
          end
          
          begin
            shadow_expire = entry.shadowExpire.pop.to_i
          rescue NoMethodError
          end
          
          begin
            shadow_flag = entry.shadowFlag.pop.to_i
          rescue NoMethodError
          end
          
          begin
            shadow_inactive = entry.shadowInactive.pop.to_i
          rescue NoMethodError
          end
          
          begin
            shadow_last_change = entry.shadowLastChange.pop.to_i
          rescue NoMethodError
          end
          
          begin
            shadow_max = entry.shadowMax.pop.to_i
          rescue NoMethodError
          end
          
          begin
            shadow_min = entry.shadowMin.pop.to_i
          rescue NoMethodError
          end
          
          begin
            shadow_warning = entry.shadowWarning.pop.to_i
          rescue NoMethodError
          end
          
          rid = sid2rid_int(entry.objectSid.pop)
          primary_group = find_group_by_rid entry.primaryGroupID.pop.to_i
          disabled = entry.userAccountControl.pop.to_i ==
                            UF_NORMAL_ACCOUNT + UF_ACCOUNTDISABLE ? true : false
          
          # Note that users add themselves to their container. We have to have
          # found the primary_group already, or we can't make the user. The
          # primary group is important information, but it is stored as a RID
          # value in the primaryGroupID AD attribute. The group membership
          # it defines is defined nowhere else however. We will print a warning
          # for any users skipped. This is why the AD object automatically
          # adds a cn=Users container.
          if primary_group
            if uid && gid
              if unix_main_group = find_group_by_gid(gid)
                nis_domain = "radum" unless nis_domain
                user = UNIXUser.new(entry.sAMAccountName.pop, container,
                                    primary_group, uid, unix_main_group,
                                    entry.loginShell.pop,
                                    entry.unixHomeDirectory.pop, nis_domain,
                                    disabled, rid)
                user.common_name = entry.cn.pop
                user.first_name = first_name if first_name
                user.middle_name = middle_name if middle_name
                user.surname = surname if surname
                user.gecos = gecos if gecos
                user.unix_password = unix_password if unix_password
                user.shadow_expire = shadow_expire if shadow_expire
                user.shadow_flag = shadow_flag if shadow_flag
                user.shadow_inactive = shadow_inactive if shadow_inactive
                user.shadow_last_change = shadow_last_change if
                                          shadow_last_change
                user.shadow_max = shadow_max if shadow_max
                user.shadow_min = shadow_min if shadow_min
                user.shadow_warning = shadow_warning if shadow_warning
              else
                puts "Warning: Main UNIX group could not be found for: " +
                     entry.sAMAccountName.pop
              end
            else
              user = User.new(entry.sAMAccountName.pop, container,
                              primary_group, disabled, rid)
              user.common_name = entry.cn.pop
              user.first_name = first_name if first_name
              user.middle_name = middle_name if middle_name
              user.surname = surname if surname
            end
          else
            puts "Warning: Windows primary group not found for: " +
                 entry.sAMAccountName.pop
          end
        end
      end
      
      # Add users to groups, which also adds the groups to the user, etc. The
      # Windows primary_group was taken care of when creating the users
      # previously.
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
                  group.add_user member_user
                end
              end
            rescue NoMethodError
            end
          end
        end
      end
      
      # Set all users and groups as loaded. This has to be done last to make
      # sure the modified attribute is correct. The modified attribute needs
      # to be false, and it is hidden from direct access by the loaded method.
      @containers.each do |container|
        container.groups.each do |group|
          group.loaded
        end
        
        container.users.each do |user|
          user.loaded
        end
      end
    end
    
    # Load the next free UID value from the Active Directory. This is a
    # convenience method that allows one to find the next free UID value.
    # This method returns the next free UID value found while searching
    # from the AD root. A return value of 0 indicates no UIDs were found.
    def load_next_uid
      all_uids = []
      base = "#{@root}"
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @ldap.search(:base => base, :filter => user_filter) do |entry|
        begin
          uid = entry.uidNumber.pop.to_i
          all_uids.push uid
        rescue NoMethodError
        end
      end
      
      all_uids.sort!
      next_uid = 0
      
      all_uids.each do |uid|
        if next_uid == 0 || next_uid + 1 == uid
          next_uid = uid
        else
          break
        end
      end
      
      next_uid + 1
    end
    
    # Load the next free GID value from the Active Directory. This is a
    # convenince method that allows one to find the next free GID value.
    # This method returns the next free GID value found while searching
    # from the AD root. A return value of 0 indicates no GIDs were found.
    def load_next_gid
      all_gids = []
      base = "#{@root}"
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
      
      @ldap.search(:base => base, :filter => group_filter) do |entry|
        begin
          gid = entry.gidNumber.pop.to_i
          all_gids.push gid
        rescue NoMethodError
        end
      end
      
      all_gids.sort!
      next_gid = 0
      
      all_gids.each do |gid|
        if next_gid == 0 || next_gid + 1 == gid
          next_gid = gid
        else
          break
        end
      end
      
      next_gid + 1
    end
    
    # Synchronize all modified Users, UNIXUsers, Groups, and UNIXGroups to
    # Active Directory. This will create entries as needed after checking to
    # make sure they do not already exist. New attributes will be added,
    # unset attributes will be removed, and modified attributes will be
    # updated automatically.
    def sync
      # First, make sure any groups that need to be created are added to Active
      # Directory.
      @containers.each do |container|
        container.groups.each do |group|
          # This method checks if the group actually needs to be created or not.
          create_group group
        end
      end
      
      # Second, make sure any users that need to be created are added to Active
      # Directory.
      @containers.each do |container|
        container.users.each do |user|
          # This method checks if the user actually needs to be created or not.
          create_user user
        end
      end
    end
    
    # Returns true if two AD objects are equal, otherwise false. Equality is
    # established by the two AD objects having the same root attribute
    # (case-insensitive).
    def ==(other)
      @root.downcase == other.root.downcase
    end
    
    # Returns true if two AD objects are equal as defined by the AD.== method.
    def eql?(other)
      self == other
    end
    
    # The String representation of the AD object.
    def to_s
      "AD [#{@root} #{@server}:#{@port}]"
    end
    
    private
    
    # Unpack a RID from the SID value in the LDAP objectSid attribute for a
    # user or group in Active Directory.
    def sid2rid_int(sid)
      sid.unpack("qV*").pop.to_i
    end
    
    # Convert a string to UTF-16LE. For ASCII characters, the result should be
    # each character followed by a NULL, so this is very easy. Windows expects
    # a UTF-16LE string for the unicodePwd attribute. Note that the password
    # Active Directory is expecting for the unicodePwd attribute has to be
    # explicitly quoted.
    def str2utf16le(str)
      ('"' + str + '"').gsub(/./) { |c| "#{c}\0" }
    end
    
    # Check the LDAP operation result code for an error message.
    def check_ldap_result
      unless @ldap.get_operation_result.code == 0
        puts "LDAP ERROR: " + @ldap.get_operation_result.message
        puts "[Error code: " + @ldap.get_operation_result.code.to_s + "]"
      end
    end
    
    # Create a Group or UNIXGroup in Active Directory. The Group or UNIXGroup
    # must have its loaded attribute set to false, which indicates it was
    # manually created. This method checks that, so it is not necessary to
    # worry about checking first. This method also makes sure the group is not
    # already in Active Directory, in case someone created a group that would
    # match one that already exists. Therefore, any Group or UNIXGroup can be
    # passed into this method.
    def create_group(group)
      unless group.loaded?
        group_filter = Net::LDAP::Filter.eq("objectclass", "group")
        # The return value will be false explicitly if the search fails,
        # otherwise it will be an array of entries. Therefore it is important
        # to check for false explicitly for a failure. A failure indicates
        # that the group needs to be created.
        found = @ldap.search(:base => group.distinguished_name,
                             :filter => group_filter, :return_result => false)
        
        # The group should not already exist of course. This is to make sure
        # it is not already there in the case it was manually created but
        # matches a group that already exists.
        if found == false
          puts "#{group.name} not found - creating..."
          
          # Note that all the attributes need to be strings in this hash.
          attr = {
            :cn => group.name,
            :groupType => group.type.to_s,
            :name => group.name,
            # All groups are of the objectclasses "top" and "group".
            :objectclass => [ "top", "group" ],
            :sAMAccountName => group.name
          }
          
          attr.merge!({
            :gidNumber => group.gid.to_s,
            :msSFU30Name => group.name,
            :msSFU30NisDomain => group.nis_domain,
            :unixUserPassword => group.unix_password
          }) if group.instance_of? UNIXGroup
          
          @ldap.add :dn => group.distinguished_name, :attributes => attr
          check_ldap_result
        else
          puts "SYNC WARNING: #{group.name} already exists. Not created."
        end
      end
    end
    
    # Create a User or UNIXUser in Active Directory. The User or UNIXUser
    # must have its loaded attribute set to false, which indicates it was
    # manually created. This method checks that, so it is not necessary to
    # worry about checking first. This method also makes sure the user is not
    # already in Active Directory, in case someone created a user that would
    # match one that already exists. Therefore, any User or UNIXUser can be
    # passed into this method.
    def create_user(user)
      unless user.loaded?
        user_filter = Net::LDAP::Filter.eq("objectclass", "user")
        # The return value will be false explicitly if the search fails,
        # otherwise it will be an array of entries. Therefore it is important
        # to check for false explicitly for a failure. A failure indicates
        # that the group needs to be created.
        found = @ldap.search(:base => user.distinguished_name,
                             :filter => user_filter, :return_result => false)
        
        # The user should not already exist of course. This is to make sure
        # it is not already there.
        if found == false
          # We need the RID of the user's primary Windows group. If the primary
          # Windows group has true for its loaded attribute, it knows its RID
          # already. If not, we need to search Active Directory to find it
          # because it might have been created.
          rid = user.primary_group.rid
          
          # If the group was loaded, we don't need to search for the group's
          # RID as the step above would have the right value.
          unless user.primary_group.loaded
            group_filter = Net::LDAP::Filter.eq("objectclass", "group")
            
            @ldap.search(:base => user.primary_group.distinguished_name,
                         :filter => group_filter) do |entry|
              rid = sid2rid_int(entry.objectSid.pop)
            end
          end
          
          if rid.nil?
            puts "SYNC ERROR: RID of #{user.primary_group.name} not found."
            return
          end
          
          puts "#{user.username} not found - creating..."
          
          # Note that all the attributes need to be strings in this hash.
          # What in the heck do we do about the Windows password?
          attr = {
            :cn => user.common_name,
            # All users are of the objectclasses "top", "person",
            # "orgainizationalPerson", and "user".
            :objectclass => [ "top", "person", "organizationalPerson", "user" ],
            :sAMAccountName => user.username,
            :userAccountControl => (UF_NORMAL_ACCOUNT + UF_PASSWD_NOTREQD +
                                    UF_ACCOUNTDISABLE).to_s
          }
          
          display_name = description = name = ""
          
          # These are optional attributes.
          unless user.first_name.nil?
            attr.merge!({ :givenName => user.first_name })
            display_name += "#{user.first_name}"
            description += "#{user.first_name}"
            name += "#{user.first_name}"
          end
          
          unless user.middle_name.nil?
            attr.merge!({ :middleName => user.middle_name })
            display_name += " #{user.middle_name}"
            description += " #{user.middle_name}"
          end
          
          unless user.surname.nil?
            attr.merge!({ :sn => user.surname })
            display_name += " #{user.surname}"
            description += " #{user.surname}"
            name += " #{user.surname}"
          end
          
          # We should set these to something in case they were not set.
          if display_name == ""
            display_name = user.username
          end
          
          if description == ""
            description = user.username
          end
          
          if name == ""
            name = user.username
          end
          
          realm = user.username + "@#{@domain}"
          
          attr.merge!({
            :displayName => display_name,
            :description => description,
            :name => name,
            :userPrincipalName => realm,
          })
          
          attr.merge!({
            :gecos => user.gecos,
            :gidNumber => user.unix_main_group.gid.to_s,
            :loginShell => user.shell,
            :msSFU30Name => user.username,
            :msSFU30NisDomain => user.nis_domain,
            :uidNumber => user.uid.to_s,
            :unixHomeDirectory => user.home_directory,
            :unixUserPassword => user.unix_password
          }) if user.instance_of? UNIXUser
          
          # The shadow file attributes are all optional, so we need to check
          # each one. The other UNIX attributes above are set to something
          # by default.
          unless user.shadow_expire.nil?
            attr.merge!({ :shadowExpire => user.shadow_expire.to_s })
          end
          
          unless user.shadow_flag.nil?
            attr.merge!({ :shadowFlag => user.shadow_flag.to_s })
          end
          
          unless user.shadow_inactive.nil?
            attr.merge!({ :shadowInactive => user.shadow_inactive.to_s })
          end
          
          unless user.shadow_last_change.nil?
            attr.merge!({ :shadowLastChange => user.shadow_last_change.to_s })
          end
          
          unless user.shadow_max.nil?
            attr.merge!({ :shadowMax => user.shadow_max.to_s })
          end
          
          unless user.shadow_min.nil?
            attr.merge!({ :shadowMin => user.shadow_min.to_s })
          end
          
          unless user.shadow_warning.nil?
            attr.merge!({ :shadowWarning => user.shadow_warning.to_s })
          end
          
          puts attr.to_yaml
          puts user.distinguished_name
          @ldap.add :dn => user.distinguished_name, :attributes => attr
          check_ldap_result
          
          # Modify the attributes for the user password and userAccountControl
          # value to enable the account.
          #
          # NOTE: HANDLE THE CASE WHERE THERE IS NO PASSWORD. Also note in the
          # documentation the user will be forced to change their password on
          # the first login.
          user_status = UF_NORMAL_ACCOUNT
          user_status += UF_ACCOUNTDISABLE if user.disabled?
          
          ops = [
             [:replace, :unicodePwd, str2utf16le(user.password)],
             [:replace, :userAccountControl, user_status.to_s]
           ]
           
           puts ops.to_yaml
           @ldap.modify :dn => user.distinguished_name, :operations => ops
           check_ldap_result
           
           # If the user has to change their password, it must be done below
           # and not in the previous step that set their password because it
           # will ignore the additional flag (which I've commented out near
           # the top of this file because it does not work now). This works.
           if user.must_change_password?
             ops = [
               [:replace, :pwdLastSet, 0.to_s]
             ]
             
             puts ops.to_yaml
             @ldap.modify :dn => user.distinguished_name, :operations => ops
             check_ldap_result
           end
           
           # The user already has the primary Windows group as Domain Users
           # based on the default actions above. If the user has a different
           # primary Windows group, it is necessary to add the user to that
           # group first (as a member in the member attribute for the group)
           # before attempting to set their primaryGroupID attribute or Active
           # Directory will refuse to do it.
           unless rid == find_group("Domain Users").rid
             ops = [
               [:add, :member, user.distinguished_name]
             ]
             
             puts ops.to_yaml
             @ldap.modify :dn => user.primary_group.distinguished_name,
                          :operations => ops
             check_ldap_result
             
             ops = [
               [:replace, :primaryGroupID, rid.to_s]
             ]
             
             puts ops.to_yaml
             @ldap.modify :dn => user.distinguished_name, :operations => ops
             check_ldap_result
          end
        else
          puts "SYNC WARNING: #{user.username} already exists. Not created."
        end
      end
    end
  end
end
