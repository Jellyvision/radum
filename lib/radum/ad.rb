# The RADUM module provides an interface to Microsoft Active Directory for
# working with users and groups. The User class represents a standard Windows
# user account. The UNIXUser class represents a Windows account that has UNIX
# attributes. Similarly, the Group class represents a standard Windows group,
# and a UNIXGroup represents a Windows group that has UNIX attributes. This
# module concentrates only on users and groups at this time.
#
# This is a pure Ruby implementation. Windows command line tools are not
# used in any way, so this will work from other platforms such as Mac OS X
# and Linux in addition to Windows.
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
  # prefixed with "load" pull data out of the Active Directory and methods
  # prefixed with "sync" push data to the Active Directory as required.
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
    # The array of Containers in the AD object.
    attr_reader :containers
    # The array of Containers set for removal in the AD object.
    attr_reader :removed_containers
    
    # Create a new AD object to represent an Active Directory environment.
    # The root is a String representation of an LDAP path, such as
    # "dc=example,dc=com". The password is used in conjunction with the
    # specified user, which defaults to Administrator
    # ("cn=Administrator,cn=Users"), to authenticate when a connection is
    # is actually utilized in data processing ("load" and "sync" prefixed
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
      @removed_containers = []
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
          @removed_containers.delete container
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
      
      unless @removed_containers.include? container
        @removed_containers.push container
      end
      
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
    
    # Returns an Array of all removed User and UNIXUser objects in the AD.
    def removed_users
      all_removed_users = []
      
      @containers.each do |container|
        container.removed_users.each do |user|
          all_removed_users.push user
        end
      end
      
      all_removed_users
    end
    
    # Find a User or UNIXUser in the AD by username. The search is
    # case-insensitive. The User or UNIXUser is returned if found, otherwise
    # nil is returned. Specify the second argument as true if you wish to
    # search for removed User or UNIXUser objects.
    def find_user(username, removed = false)
      if removed
        search_users = removed_users
      else
        search_users = users
      end
      
      found = search_users.find do |user|
        # This relies on the fact that usernames (sAMAccountName) must be
        # unique in a directory.
        user.username.downcase == username.downcase
      end
      
      return found if found
      return nil
    end
    
    # Find a User or UNIXUser in the AD by RID. The User or UNIXUser is
    # returned if found, otherwise nil is returned. Specify the second argument
    # as true if you wish to search for removed User or UNIXUser objects.
    def find_user_by_rid(rid, removed = false)
      if removed
        search_users = removed_users
      else
        search_users = users
      end
      
      found = search_users.find do |user|
        user.rid == rid
      end
      
      return found if found
      return nil
    end
    
    # Find a UNIXUser in the AD by UID. The UNIXUser is returned if found,
    # otherwise nil is returned. Specify the second argument as true if you
    # wish to search for removed UNIXUser objects.
    def find_user_by_uid(uid, removed = false)
      if removed
        search_users = removed_users
      else
        search_users = users
      end
      
      found = search_users.find do |user|
        user.uid == uid if user.instance_of? UNIXUser
      end
      
      return found if found
      return nil
    end
    
    # Find a User or UNIXUser in the AD by distinguished name. The User or
    # UNIXUser is returned if found, otherwise nil is returned. Specify the
    # second argument as true if you wish to search for removed User or
    # UNIXUser objects.
    def find_user_by_dn(dn, removed = false)
      if removed
        search_users = removed_users
      else
        search_users = users
      end
      
      found = search_users.find do |user|
        user.distinguished_name.downcase == dn.downcase
      end
      
      return found if found
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
    
    # Returns an Array of all removed Group and UNIXGroup objects in the AD.
    def removed_groups
      all_removed_groups = []
      
      @containers.each do |container|
        container.removed_groups.each do |group|
          all_removed_groups.push group
        end
      end
      
      all_removed_groups
    end
    
    # Find a Group or UNIXGroup in the AD by name. The search is
    # case-insensitive. The Group or UNIXGroup is returned if found, otherwise
    # nil is returned. Specify the second argument as true if you wish to
    # search for removed Group or UNIXGroup objects.
    def find_group(name, removed = false)
      if removed
        search_groups = removed_groups
      else
        search_groups = groups
      end
      
      found = search_groups.find do |group|
        # This relies on the fact that group names must be unique in a
        # directory.
        group.name.downcase == name.downcase
      end
      
      return found if found
      return nil
    end
    
    # Find a Group or UNIXGroup in the AD by RID. The Group or UNIXGroup is
    # returned if found, otherwise nil is returned. Specify the second argument
    # as true if you wish to search for removed Group or UNIXGroup objects.
    def find_group_by_rid(rid, removed = false)
      if removed
        search_groups = removed_groups
      else
        search_groups = groups
      end
      
      found = search_groups.find do |group|
        group.rid == rid
      end
      
      return found if found
      return nil
    end
    
    # Find a UNIXGroup in the AD by GID. The UNIXGroup is returned if found,
    # otherwise nil is returned. Specify the second argument as true if you
    # wish to search for removed UNIXGroup objects.
    def find_group_by_gid(gid, removed = false)
      if removed
        search_groups = removed_groups
      else
        search_groups = groups
      end
      
      found = search_groups.find do |group|
        group.gid == gid if group.instance_of? UNIXGroup
      end
      
      return found if found
      return nil
    end
    
    # Find a Group or UNIXGroup in the AD by distinguished name. The Group or
    # UNIXGroup is returned if found, otherwise nil is returned. Specify the
    # second argument as true if you wish to search for removed Group or
    # UNIXGroup objects.
    def find_group_by_dn(dn, removed = false)
      if removed
        search_groups = removed_groups
      else
        search_groups = groups
      end
      
      found = search_groups.find do |group|
        group.distinguished_name.downcase == dn.downcase
      end
      
      return found if found
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
      # TO DO: WE SHOULD NOT ALLOW LOADING MORE THAN ONCE? SEE THE OTHER TO DO
      # COMMENTS IN THIS CODE.
      
      # Find all the groups first. We might need one to represent the main
      # group of a UNIX user.
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
      
      @containers.each do |container|
        @ldap.search(:base => container.distinguished_name,
                     :filter => group_filter) do |entry|
          attr = group_ldap_entry_attr entry
          
          # TO DO: WHAT IF THE USER ALREADY CREATED A GROUP OR UNIXGROUP THAT
          # WE ARE TRYING TO LOAD NOW? THE NEW WILL FAIL IN THAT CASE. SHOULD
          # WE OVERWRITE THAT OR WHAT? THE SAME PROBLEM IS PRESENT IN THE
          # CREATE_GROUP() METHOD.
          
          # Note that groups add themselves to their container.
          if attr[:gid]
            attr[:nis_domain] = "radum" unless attr[:nis_domain]
            group = UNIXGroup.new(attr[:name], container, attr[:gid],
                                  attr[:type], attr[:nis_domain], attr[:rid])
            group.unix_password = attr[:unix_password] if attr[:unix_password]
          else
            Group.new(attr[:name], container, attr[:type], attr[:rid])
          end 
        end
      end
      
      # Find all the users. The main UNIX group must be set for UNIXUser
      # objects, so it will be necessary to search for that.
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @containers.each do |container|
        @ldap.search(:base => container.distinguished_name,
                     :filter => user_filter) do |entry|
          attr = user_ldap_entry_attr entry
          
          # TO DO: WHAT IF THE USER ALREADY CREATED A USER OR UNIXUSER THAT
          # WE ARE TRYING TO LOAD NOW? THE NEW WILL FAIL IN THAT CASE. SHOULD
          # WE OVERWRITE THAT OR WHAT? THE SAME PROBLEM IS PRESENT IN THE
          # CREATE_USER() METHOD.
          
          # Note that users add themselves to their container. We have to have
          # found the primary_group already, or we can't make the user. The
          # primary group is important information, but it is stored as a RID
          # value in the primaryGroupID AD attribute. The group membership
          # it defines is defined nowhere else however. We will print a warning
          # for any users skipped. This is why the AD object automatically
          # adds a cn=Users container.
          if attr[:primary_group]
            if attr[:uid] && attr[:gid]
              if unix_main_group = find_group_by_gid(attr[:gid])
                attr[:nis_domain] = "radum" unless attr[:nis_domain]
                user = UNIXUser.new(attr[:username], container,
                                    attr[:primary_group], attr[:uid],
                                    unix_main_group, attr[:shell],
                                    attr[:home_directory],
                                    attr[:nis_domain], attr[:disabled?],
                                    attr[:rid])
                user.common_name = attr[:common_name]
                user.first_name = attr[:first_name] if attr[:first_name]
                user.middle_name = attr[:middle_name] if attr[:middle_name]
                user.surname = attr[:surname] if attr[:surname]
                user.gecos = attr[:gecos] if attr[:gecos]
                user.unix_password = attr[:unix_password] if
                                     attr[:unix_password]
                user.shadow_expire = attr[:shadow_expire] if
                                     attr[:shadow_expire]
                user.shadow_flag = attr[:shadow_flag] if attr[:shadow_flag]
                user.shadow_inactive = attr[:shadow_inactive] if
                                       attr[:shadow_inactive]
                user.shadow_last_change = attr[:shadow_last_change] if
                                          attr[:shadow_last_change]
                user.shadow_max = attr[:shadow_max] if attr[:shadow_max]
                user.shadow_min = attr[:shadow_min] if attr[:shadow_min]
                user.shadow_warning = attr[:shadow_warning] if
                                      attr[:shadow_warning]
              else
                puts "Warning: Main UNIX group could not be found for: " +
                     attr[:username]
                puts "Not loading #{attr[:username]}."
              end
            else
              user = User.new(attr[:username], container, attr[:primary_group],
                              attr[:disabled?], attr[:rid])
              user.common_name = attr[:common_name]
              user.first_name = attr[:first_name] if attr[:first_name]
              user.middle_name = attr[:middle_name] if attr[:middle_name]
              user.surname = attr[:surname] if attr[:surname]
            end
          else
            puts "Warning: Windows primary group not found for: " +
                 attr[:username]
            puts "Not loading #{attr[:username]}."
          end
        end
      end
      
      # Add users to groups, which also adds the groups to the user, etc. The
      # Windows primary_group was taken care of when creating the users
      # previously.
      groups.each do |group|
        entry = @ldap.search(:base => group.distinguished_name,
                             :filter => group_filter).pop
        
        begin
          entry.member.each do |member|
            # Groups can have groups or users as members, unlike UNIX where
            # groups cannot contain group members.
            member_group = find_group_by_dn member
            
            if member_group
              group.add_group member_group
            end
            
            member_user = find_user_by_dn member
            
            if member_user
              group.add_user member_user
            end
          end
        rescue NoMethodError
        end
      end
      
      # Set all users and groups as loaded. This has to be done last to make
      # sure the modified attribute is correct. The modified attribute needs
      # to be false, and it is hidden from direct access by the loaded method.
      groups.each do |group|
        group.set_loaded
      end
        
      users.each do |user|
        user.set_loaded
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
      # First, remove any users that have been removed from a container here.
      # We need to remove users first because a group cannot be removed if
      # a user has it as their primary Windows group. Just in case, we remove
      # the removed users first. The same applies if the group is some other
      # user's main UNIX group. The code in this module makes sure that doesn't
      # happen for objects it knows about, but there could be others in Active
      # Directory the module does not know about.
      removed_users.each do |user|
        remove_user user
      end
      
      # Second, remove any groups that have been removed from a contianer here.
      removed_groups.each do |group|
        # This method checks if the group is some other user's primary Windows
        # group by searching the entire Active Directory. A group cannot be
        # removed if it is any user's primary Windows group. The same applies
        # if the group is some other user's main UNIX group. The code in this
        # module makes sure that doesn't happen for objects it knows about, but
        # there could be others in Active Directory the module does not know
        # about.
        remove_group group
      end
      
      # Third, create any containers or organizational units that do not already
      # exist.
      @containers.each do |container|
        # This method only creates containers that do not already exist. Since
        # containers are not loaded directly at first, their status is directly
        # tested in the method.
        create_container container
      end
      
      # Fourth, make sure any groups that need to be created are added to Active
      # Directory.
      groups.each do |group|
        # This method checks if the group actually needs to be created or not.
        create_group group
      end
      
      # Fifth, make sure any users that need to be created are added to Active
      # Directory.
      users.each do |user|
        # This method checks if the user actually needs to be created or not.
        create_user user
      end
      
      # Sixth, update any modified attributes on each group.
      groups.each do |group|
        # This method figures out what attributes need to be updated when
        # compared to Active Directory. All objects should exist in Active
        # Directory at this point, but the method handles cases where the
        # object is not in Active Directory by skipping the update in that
        # case.
        update_group group
      end
            
      # Finally, update any modified attributs on each user.
      users.each do |user|
        # This method figures out what attributes need to be updated when
        # compared to Active Directory. All objects should exist in Active
        # Directory at this point, but the method handles cases where the
        # object is not in Active Directory by skipping the update in that
        # case.
        update_user user
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
    
    # Return a random number character as a string.
    def random_number
      srand
      (rand 10).to_s
    end
    
    # Return a random lowercase letter as a string.
    def random_lowercase
      srand
      sprintf "%c", ((rand 26) + 97)
    end
    
    # Return a random uppercase letter as a string.
    def random_uppercase
      random_lowercase.swapcase
    end
    
    # Return a random symbol as a string.
    def random_symbol
      srand
      
      case rand 4
      when 0
        code = rand(15) + 33
      when 1
        code = rand(7) + 58
      when 2
        code = rand(6) + 91
      when 3
        code = rand(4) + 123
      end
      
      sprintf "%c", code
    end
    
    # Return a random 8 character password as a string. There is a formula to
    # try and avoid any problems with Active Directory password requirements.
    # If you don't like this, supply your own password for User and UNIXUser
    # objects.
    def random_password
      random_lowercase + random_number + random_lowercase + random_uppercase +
      random_symbol + random_number + random_uppercase + random_symbol
    end
    
    # Return a hash with an Active Directory group's base LDAP attributes. The
    # key is the RADUM group attribute name and the value is the computed value
    # from the group's attributes in Active Directory.
    def group_ldap_entry_attr(entry)
      attr = {}
      # These are attributes that might be empty. If they are empty,
      # a NoMethodError exception will be raised. We have to check each
      # individually and set an initial indicator value (nil). All the
      # other attributes should exist and do not require this level of
      # checking.
      attr[:gid] = nil
      attr[:nis_domain] = nil
      attr[:unix_password] = nil
      
      begin
        attr[:gid] = entry.gidNumber.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:nis_domain] = entry.msSFU30NisDomain.pop
      rescue NoMethodError
      end
      
      begin
        attr[:unix_password] = entry.unixUserPassword.pop
      rescue NoMethodError
      end
      
      attr[:name] = entry.name.pop
      attr[:rid] = sid2rid_int(entry.objectSid.pop)
      attr[:type] = entry.groupType.pop.to_i
      return attr
    end
    
    # Return a hash with an Active Directory user's base LDAP attributes. The
    # key is the RADUM user attribute name and the value is the computed value
    # from the user's attributes in Active Directory.
    def user_ldap_entry_attr(entry)
      attr = {}
      # These are attributes that might be empty. If they are empty,
      # a NoMethodError exception will be raised. We have to check each
      # individually and set an initial indicator value (nil). All the
      # other attributes should exist and do not require this level of
      # checking.
      attr[:first_name] = nil
      attr[:middle_name] = nil
      attr[:surname] = nil
      attr[:uid] = nil
      attr[:gid] = nil
      attr[:nis_domain] = nil
      attr[:gecos] = nil
      attr[:unix_password] = nil
      attr[:shadow_expire] = nil
      attr[:shadow_flag] = nil
      attr[:shadow_inactive] = nil
      attr[:shadow_last_change] = nil
      attr[:shadow_max] = nil
      attr[:shadow_min] = nil
      attr[:shadow_warning] = nil
      attr[:shell] = nil
      attr[:home_directory] = nil
      
      begin
        attr[:first_name] = entry.givenName.pop
      rescue NoMethodError
      end
      
      begin
        attr[:middle_name] = entry.middleName.pop
      rescue NoMethodError
      end
      
      begin
        attr[:surname] = entry.sn.pop
      rescue NoMethodError
      end
      
      begin
        attr[:uid] = entry.uidNumber.pop.to_i
      rescue NoMethodError
      end

      begin
        attr[:gid] = entry.gidNumber.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:nis_domain] = entry.msSFU30NisDomain.pop
      rescue NoMethodError
      end
      
      begin
        attr[:gecos] = entry.gecos.pop
      rescue NoMethodError
      end
      
      begin
        attr[:unix_password] = entry.unixUserPassword.pop
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_expire] = entry.shadowExpire.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_flag] = entry.shadowFlag.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_inactive] = entry.shadowInactive.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_last_change] = entry.shadowLastChange.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_max] = entry.shadowMax.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_min] = entry.shadowMin.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shadow_warning] = entry.shadowWarning.pop.to_i
      rescue NoMethodError
      end
      
      begin
        attr[:shell] = entry.loginShell.pop
      rescue NoMethodError
      end
      
      begin
        attr[:home_directory] = entry.unixHomeDirectory.pop
      rescue NoMethodError
      end
      
      attr[:common_name] = entry.cn.pop
      attr[:disabled?] = entry.userAccountControl.pop.to_i ==
                         UF_NORMAL_ACCOUNT + UF_ACCOUNTDISABLE ? true : false
      attr[:primary_group] = find_group_by_rid entry.primaryGroupID.pop.to_i
      attr[:rid] = sid2rid_int(entry.objectSid.pop)
      attr[:username] = entry.sAMAccountName.pop
      return attr
    end
    
    # Check the LDAP operation result code for an error message.
    def check_ldap_result
      unless @ldap.get_operation_result.code == 0
        puts "LDAP ERROR: " + @ldap.get_operation_result.message
        puts "[Error code: " + @ldap.get_operation_result.code.to_s + "]"
      end
    end
    
    # Create a Container in Active Directory. Each Container is searched for
    # directly and created if it does not already exist. This method also
    # automatically creates parent containers as required. This is safe to
    # do, even if one of those was also passed to this method later (since it
    # would then be found).
    def create_container(container)
      distinguished_name = @root
      # This depends on the fact that the Container name had all spaces stripped
      # out in the initialize() method of the Container class.
      container.name.split(/,/).reverse.each do |current_name|
        # We have to keep track of the current path so that we have a
        # distinguished name to work wtih.
        distinguished_name = "#{current_name},#{distinguished_name}"
        
        if current_name =~ /^[Oo][Uu]=/
          type = "organizationalUnit"
        elsif current_name =~ /^[Cc][Nn]=/
          type = "container"
        else
          puts "SYNC ERROR: " + container.name + " ( #{current_name}) - " +
               "unknown Container type."
          return
        end
        
        container_filter = Net::LDAP::Filter.eq("objectclass", type)
        # The return value will be false explicitly if the search fails,
        # otherwise it will be an array of entries. Therefore it is important
        # to check for false explicitly for a failure. A failure indicates
        # that the container needs to be created.
        found = @ldap.search(:base => distinguished_name,
                             :filter => container_filter,
                             :return_result => false)
        
        if found == false
          puts "#{distinguished_name} not found - creating..."
          
          # Note that all the attributes need to be strings in the attr hash.
          if type == "organizationalUnit"
            attr = {
              :name => current_name.split(/,/)[0].gsub(/[Oo][Uu]=/, ""),
              :objectclass => ["top", "organizationalUnit"]
            }
          elsif type == "container"
            name = current_name.split(/,/)[0].gsub(/[Cc][Nn]=/, "")
            
            attr = {
              :cn => name,
              :name => name,
              :objectclass => ["top", "container"]
            }
          else
            puts "SYNC ERROR: " + container.name + " ( #{current_name}) - " +
                 "unknown Container type."
            return
          end
          
          @ldap.add :dn => distinguished_name, :attributes => attr
          check_ldap_result
        end
      end
    end
    
    # Remove a Group or UNIXGroup from Active Directory.
    def remove_group(group)
      # First check to make sure the group is not the primary Windows group
      # or main UNIX group for any user in Active Directory. We could probably
      # rely on the attempt to delete the group failing, but I don't like doing
      # that. Yes, it is much less efficient this way, but removing a group is
      # not very common in my experience. Also note that this would probably not
      # fail for a main UNIX group because that's pretty much "tacked" onto
      # the standard Windows Active Directory logic (at least, I have been
      # able to remove a group that was someone's main UNIX group before, but
      # not their primary Windows group).
      found_primary = []
      found_unix = []
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @ldap.search(:base => @root, :filter => user_filter) do |entry|
        rid = entry.primaryGroupID.pop.to_i
        found_primary.push entry.dn if rid == group.rid
        
        if group.instance_of? UNIXGroup
          begin
            gid = entry.gidNumber.pop.to_i
            found_unix.push entry.dn if gid == group.gid
          rescue NoMethodError
          end
        end
      end
      
      if found_primary.empty? && found_unix.empty?
        puts "Removing group #{group.name}."
        @ldap.delete :dn => group.distinguished_name
        check_ldap_result
      else
        puts "Cannot remove group #{group.name}:"
        
        unless found_primary.empty?
          puts "#{group.name} is the primary Windows group for the users:"
          
          found_primary.each do |user|
            puts "\t#{user}"
          end
        end
        
        unless found_unix.empty?
          puts "#{group.name} is the main UNIX group for the users:"
          
          found_unix.each do |user|
            puts "\t#{user}"
          end
        end
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
            :objectclass => ["top", "group"],
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
          # At this point, we need to pull the RID value back out and set it
          # because it is needed later.
          entry = @ldap.search(:base => group.distinguished_name,
                               :filter => group_filter).pop
          group.set_rid sid2rid_int(entry.objectSid.pop)
          # Note: unlike a user, the group cannot be considered loaded at this
          # point because we have not handled any group memberships that might
          # have been set. Users at this poing in the create_user() method
          # can be considered loaded. Just noting this for my own reference.
        else
          # TO DO: SHOULD WE OVERWRITE THE GROUP OR WHAT? SEE THE LOAD() METHOD
          # COMMENT.
          puts "SYNC WARNING: #{group.name} already exists. Not created."
        end
      end
    end
    
    # Update a Group or UNIXGroup in Active Directory. This method automatically
    # determines which attributes to update. The Group or UNIXGroup object must
    # exist in Active Directory or this method does nothing. This is checked, so
    # it is safe to pass any Group or UNIXGroup object to this method.
    def update_group(group)
      if group.modified?
        puts "Updating #{group.class} #{group.name}..."
        group_filter = Net::LDAP::Filter.eq("objectclass", "group")
        entry = @ldap.search(:base => group.distinguished_name,
                             :filter => group_filter).pop
        attr = group_ldap_entry_attr entry
        ops = []
        
        attr.keys.each do |key|
          # All keys in the attr hash apply to UNIXGroups, but some do not apply
          # to Groups. This is the easiest way to filter out inappropriate
          # checking.
          begin
            obj_value = group.send(key)
          rescue NoMethodError
            next
          end
          
          ad_value = attr[key]
          puts "\t#{key}: #{ad_value} =? #{obj_value}"
          
          if ad_value != obj_value
            case key
            when :nis_domain
              ops.push [:replace, :msSFU30NisDomain, obj_value]
            when :unix_password
              ops.push [:replace, :unixUserPassword, obj_value]
            end
          end
        end
        
        begin
          entry.member.each do |member|
            # Groups can contain users and groups, so we need to check both
            # just in case. You can't tell from the DN which is which here.
            # First we remove any DNs that we've explicitly removed. Anything
            # we don't know about will be ignored.
            #
            # This check finds users or groups that were removed from the
            # container. This means the user has been deleted from Active
            # Directory in the AD object. It also finds users or groups that
            # were explicitly removed from the group.
            removed_group = find_group_by_dn(member, true)
            removed_user = find_user_by_dn(member, true)
            removed_group_membership = find_group_by_dn(member)
            
            unless group.removed_groups.include?(removed_group_membership)
              removed_group_membership = false
            end
            
            removed_user_membership = find_user_by_dn(member)
            
            unless group.removed_users.include?(removed_user_membership)
              removed_user_membership = false
            end
            
            if removed_group || removed_user || removed_group_membership ||
               removed_user_membership
              ops.push [:delete, :member, member]
              user = removed_user || removed_user_membership
              
              if user && user.instance_of?(UNIXUser) &&
                 group.instance_of?(UNIXGroup)
                # There is a chance the user was never a UNIX member of this
                # UNIXGroup. This happens if the UNIX main group is changed
                # and then the user is removed from the group as well. We
                # should really also search the memberUid attribute, but
                # really... it should always match up with msSFU30PosixMember.
                begin
                  found = entry.msSFU30PosixMember.find do |member|
                    item.distinguished_name.downcase == member.downcase
                  end
                  
                  if found
                    ops.push [:delete, :memberUid, user.username]
                    ops.push [:delete, :msSFU30PosixMember, member]
                  end
                rescue NoMethodError
                end
              end
            end
          end
          
          # Now add any users or groups that are not already in the members
          # attribute array. We don't want to add the same thing twice because
          # this actually seems to duplicate the entries.
          (group.users + group.groups).each do |item|
            found = entry.member.find do |member|
              item.distinguished_name.downcase == member.downcase
            end
            
            ops.push [:add, :member, item.distinguished_name] unless found
            
            if item.instance_of?(UNIXUser) && group.instance_of?(UNIXGroup) &&
               group != item.unix_main_group
              begin
                # We should really also search the memberUid attribute, but
                # really... it should always match up with msSFU30PosixMember.
                found = entry.msSFU30PosixMember.find do |member|
                  item.distinguished_name.downcase == member.downcase
                end
                
                unless found
                  ops.push [:add, :memberUid, item.username]
                  ops.push [:add, :msSFU30PosixMember, item.distinguished_name]
                end
              rescue NoMethodError
              end
            end
          end
        rescue NoMethodError
        end
        
        unless ops.empty?
          puts ops.to_yaml
          @ldap.modify :dn => group.distinguished_name, :operations => ops
          check_ldap_result
          # At this point the group is the equivalent of a loaded group. Calling
          # this flags that fact as well as setting the hidden modified
          # attribute to false since we are up to date now.
          group.set_loaded
        end
      end
    end
    
    # Remove a User or UNIXUser from Active Directory.
    def remove_user(user)
      @ldap.delete :dn => user.distinguished_name
      check_ldap_result
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
        # that the user needs to be created.
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
          unless user.primary_group.loaded?
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
          attr = {
            :cn => user.common_name,
            # All users are of the objectclasses "top", "person",
            # "orgainizationalPerson", and "user".
            :objectclass => ["top", "person", "organizationalPerson", "user"],
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
          if user.instance_of? UNIXUser
            unless user.shadow_expire.nil?
              attr.merge!({:shadowExpire => user.shadow_expire.to_s})
            end
            
            unless user.shadow_flag.nil?
              attr.merge!({:shadowFlag => user.shadow_flag.to_s})
            end
          
            unless user.shadow_inactive.nil?
              attr.merge!({:shadowInactive => user.shadow_inactive.to_s})
            end
            
            unless user.shadow_last_change.nil?
              attr.merge!({:shadowLastChange => user.shadow_last_change.to_s})
            end
            
            unless user.shadow_max.nil?
              attr.merge!({:shadowMax => user.shadow_max.to_s})
            end
            
            unless user.shadow_min.nil?
              attr.merge!({:shadowMin => user.shadow_min.to_s})
            end
            
            unless user.shadow_warning.nil?
              attr.merge!({:shadowWarning => user.shadow_warning.to_s})
            end
          end
          
          puts attr.to_yaml
          puts user.distinguished_name
          @ldap.add :dn => user.distinguished_name, :attributes => attr
          check_ldap_result
          
          # Modify the attributes for the user password and userAccountControl
          # value to enable the account.
          user_status = UF_NORMAL_ACCOUNT
          user_status += UF_ACCOUNTDISABLE if user.disabled?
          
          if user.password.nil?
            user.password = random_password
            puts "Generated password #{user.password} for #{user.username}."
          end
          
          ops = [
            [:replace, :unicodePwd, str2utf16le(user.password)],
            [:replace, :userAccountControl, user_status.to_s]
          ]
          
          puts ops.to_yaml
          @ldap.modify :dn => user.distinguished_name, :operations => ops
          check_ldap_result
          
          # Set the user's password to nil. When a password has a value, that
          # means we need to set it, otherwise it should be nil. We just
          # set it, so we don't want the update set to try and set it again.
          user.password = nil
          
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
            # At this point, we need to pull the RID value back out and set it
            # because it is needed later. Actually, it isn't for users, but
            # I am pretending it is just as important because I am tracking
            # RIDs anyway (they are in a flat namespace).
            entry = @ldap.search(:base => user.distinguished_name,
                                 :filter => user_filter).pop
            user.set_rid sid2rid_int(entry.objectSid.pop)
            # The user has now been made a regular member of the Domain Users
            # Windows group. This has been handled in Active Directory for us,
            # but now we want to reflect that in the Domain Users Group object
            # here.
            find_group("Domain Users").add_user user
          end
          
          # At this point the user is the equivalent as a loaded user.
          # Calling this flags that fact as well as setting the hidden
          # modified attribute to false since we are up to date now. Note
          # that the groups attribute is still not 100% accurate. It will
          # be dealt with later when groups are dealt with.
          user.set_loaded
        else
          # TO DO: SHOULD WE OVERWRITE THE USER OR WHAT? SEE THE LOAD() METHOD
          # COMMENT.
          puts "SYNC WARNING: #{user.username} already exists. Not created."
        end
      end
    end
    
    # Update a User or UNIXUser in Active Directory. This method automatically
    # determines which attributes to update. The User or UNIXUser object must
    # exist in Active Directory or this method does nothing. This is checked, so
    # it is safe to pass any User or UNIXUser object to this method.
    def update_user(user)
      if user.modified?
        puts "Updating #{user.class} #{user.username}..."
        user_filter = Net::LDAP::Filter.eq("objectclass", "user")
        entry = @ldap.search(:base => user.distinguished_name,
                             :filter => user_filter).pop
        attr = user_ldap_entry_attr entry
        ops = []
        
        attr.keys.each do |key|
          # All keys in the attr hash apply to UNIXUsers, but most do not apply
          # to Users. This is the easiest way to filter out inappropriate
          # checking.
          begin
            obj_value = user.send(key)
          rescue NoMethodError
            next
          end
          
          ad_value = attr[key]
          puts "\t#{key}: #{ad_value} =? #{obj_value}"
          
          if ad_value != obj_value
            case key
            when :disabled?
              user_status = UF_NORMAL_ACCOUNT
              user_status += UF_ACCOUNTDISABLE if obj_value
              ops.push [:replace, :userAccountControl, user_status.to_s]
            when :first_name
              ops.push [:replace, :givenName, obj_value]
            when :middle_name
              ops.push [:replace, :middleName, obj_value]
            when :surname
              ops.push [:replace, :sn, obj_value]
            when :primary_group
              @ldap.modify :dn => user.primary_group.distinguished_name,
                           :operations => [[:add, :member,
                                            user.distinguished_name]]
              check_ldap_result
              ops.push [:replace, :primaryGroupID, user.primary_group.rid.to_s]
            when :common_name
              ops.push [:replace, :cn, obj_value]
            when :shell
              ops.push [:replace, :loginShell, obj_value]
            when :home_directory
              ops.push [:replace, :unixHomeDirectory, obj_value]
            when :nis_domain
              ops.push [:replace, :msSFU30NisDomain, obj_value]
            when :gecos
              ops.push [:replace, :gecos, obj_value]
            when :unix_password
              ops.push [:replace, :unixUserPassword, obj_value]
            when :shadow_expire
              ops.push [:replace, :shadowExpire, obj_value.to_s]
            when :shadow_flag
              ops.push [:replace, :shadowFlag, obj_value.to_s]
            when :shadow_inactive
              ops.push [:replace, :shadowInactive, obj_value.to_s]
            when :shadow_last_change
              ops.push [:replace, :shadowLastChange, obj_value.to_s]
            when :shadow_max
              ops.push [:replace, :shadowMax, obj_value.to_s]
            when :shadow_min
              ops.push [:replace, :shadowMin, obj_value.to_s]
            when :shadow_warning
              ops.push [:replace, :shadowWarning, obj_value.to_s]
            when :gid
              ops.push [:replace, :gidNumber, obj_value.to_s]
            end
          end
        end
        
        # If the password is set, change the user's password. Otherwise this
        # will be nil.
        unless user.password.nil?
          ops.push [:replace, :unicodePwd, str2utf16le(user.password)]
          # Set the user's password to nil. When a password has a value, that
          # means we need to set it, otherwise it should be nil. We just
          # set it, so we don't want the update set to try and set it again.
          user.password = nil
        end
        
        # Force the user to change their password if that was set.
        if user.must_change_password?
          ops.push [:replace, :pwdLastSet, 0.to_s]
        end
        
        unless ops.empty?
          puts ops.to_yaml
          @ldap.modify :dn => user.distinguished_name, :operations => ops
          check_ldap_result
          # At this point the user is the equivalent as a loaded user. Calling
          # this flags that fact as well as setting the hidden modified
          # attribute to false since we are up to date now.
          user.set_loaded
        end
      end
    end
  end
end
