require 'rubygems'
gem 'ruby-net-ldap', '~> 0.0'
require 'net/ldap'

# The RADUM module provides an interface to Microsoft's Active Directory for
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
  # (with advanced attribute editing enabled or with the ADSI Edit tool), these
  # show up as the Fixnum values below. We are going to stick with that, even
  # though it is lame. I could not pull these out as Bignum objects. Some
  # of these are small enough to be Fixnums though, so I left them as their
  # hex values. These values correspond to the LDAP groupType attribute for
  # group objects.
  GROUP_DOMAIN_LOCAL_SECURITY = -2147483644
  GROUP_DOMAIN_LOCAL_DISTRIBUTION = 0x4
  GROUP_GLOBAL_SECURITY = -2147483646
  GROUP_GLOBAL_DISTRIBUTION = 0x2
  GROUP_UNIVERSAL_SECURITY = -2147483640
  GROUP_UNIVERSAL_DISTRIBUTION = 0x8
  
  # This is a convenience method to return a String representation of a
  # Group's or UNIXGroup's type attribute, which has the value of one of the
  # group type RADUM constants.
  def RADUM.group_type_to_s(type)
    case type
    when RADUM::GROUP_DOMAIN_LOCAL_SECURITY
      "GROUP_DOMAIN_LOCAL_SECURITY"
    when RADUM::GROUP_DOMAIN_LOCAL_DISTRIBUTION
      "GROUP_DOMAIN_LOCAL_DISTRIBUTION"
    when RADUM::GROUP_GLOBAL_SECURITY
      "GROUP_GLOBAL_SECURITY"
    when RADUM::GROUP_GLOBAL_DISTRIBUTION
      "GROUP_GLOBAL_DISTRIBUTION"
    when RADUM::GROUP_UNIVERSAL_SECURITY
      "GROUP_UNIVERSAL_SECURITY"
    when RADUM::GROUP_UNIVERSAL_DISTRIBUTION
      "GROUP_UNIVERSAL_DISTRIBUTION"
    else "UNKNOWN"
    end
  end
  
  # User status constants.
  #
  # These are the userAccountControl values for Users and UNIXUsers as far as
  # I am aware from direct testing. These are small enough to be represented
  # as Fixnums.
  USER_DISABLED = 0x202
  USER_ENABLED = 0x200
  
  # The Container class represents a directory entry which contains users and
  # groups, usually an orgainizational unit (OU).
  class Container
    # The String represenation of the Container's name.
    attr_reader :name
    # The AD object the Container belongs to.
    attr_reader :directory
    # An Array of User or UNIXUser objects that are in this Container.
    attr_reader :users
    # An Array of Group or UNIXGroup objects that are in this Container.
    attr_reader :groups
    # True if the Container has been removed from the AD, false
    # otherwise. This is set by the AD if the Container is removed.
    attr :removed, true
    
    # The Container object automatically adds itself to the AD object
    # specified. The name should be the LDAP distinguishedName attribute
    # without the AD root path component:
    #
    #   ad = RADUM::AD.new('dc=example,dc=com', 'password',
    #                      'cn=Administrator,cn=Users', '192.168.1.1')
    #   cn = RADUM::Container.new("ou=People", ad)
    #
    # Spaces are removed from the name. The Container must not already be
    # in the AD or a RuntimeError is raised.
    def initialize(name, directory) # :doc:
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
    
    # Add User and UNIXUser objects which were previously removed and had
    # their removed attribute set. User and UNIXUser objects automatically
    # add themselves to their Container object, so this is only needed when
    # adding a removed User or UNIXUser object back into the Container.
    # A removed User or UNIXUser object must have been a member of the
    # Container in order to be added back into it. If this is not true, a
    # RuntimeError is raised. If successful, the User or UNIXUser object's
    # removed attribute is set to false.
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
    
    # Remove a User or UNIXUser object from the Container. This sets the
    # User or UNIXUser object's removed attribute to true.
    def remove_user(user)
      @users.delete user
      @directory.rids.delete user.rid if user.rid
      @directory.uids.delete user.uid if user.instance_of? UNIXUser
      user.removed = true
    end
    
    # Add Group and UNIXGroup objects which were previously removed and had
    # their removed attribute set. Group and UNIXGroup objects automatically
    # add themselves to their Container object, so this is only needed when
    # adding a removed Group or UNIXGroup object back into the Container.
    # A removed Group or UNIXGroup object must have been a member of the
    # Container in order to be added back into it. If this is not true, a
    # RuntimeError is raised. If successful, the Group or UNIXGroup object's
    # removed attribute is set to false.
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
    
    # Remove a Group or UNIXGroup object from the Container. This sets the
    # Group or UNIXGroup object's removed attribute to true. A Group cannot
    # be removed if it is still any User's primary Windows group. A UNIXGroup
    # cannot be removed if it is any User's main UNIX group. In both cases,
    # a RuntimeError will be raised.
    def remove_group(group)
      # We cannot remove a group that still has a user referencing it as their
      # primary_group or unix_main_group.
      @directory.users.each do |user|
        if group == user.primary_group
          raise "Cannot remove group: it is a User's primary_group."
        end
        
        if user.instance_of? UNIXUser
          if group == user.unix_main_group
            raise "Cannot remove group: it is a UNIXUser's unix_main_group."
          end
        end
      end
      
      @groups.delete group
      @directory.rids.delete group.rid if group.rid
      @directory.gids.delete group.gid if group.instance_of? UNIXGroup
      group.removed = true
    end
    
    # The String representation of the Container object.
    def to_s
      "Container [#{@name},#{@directory.root}]"
    end
  end
  
  # The User class represents a standard Windows user account.
  class User
    # The User's username. This corresponds to the LDAP sAMAccountName
    # and msSFU30Name attributes. This is also used for part of the
    # LDAP userPrincipalName attribute.
    attr_reader :username
    # The Container object the User belongs to.
    attr_reader :container
    # The RID of the User object. This corresponds to part of the LDAP
    # objectSid attribute. This is set when the User is loaded by AD.load
    # from the AD object the Container belogs to. This attribute should not be
    # specified in the User.new method when creating a new User by hand.
    attr_reader :rid
    # The LDAP distinguishedName attribute for this User. This can be modified
    # by setting the common name using the User.common_name= method.
    attr_reader :distinguished_name
    # The Group or UNIXGroup objects the User is a member of. Users are logical
    # members of their primary_group as well, but that is not added to the
    # groups array directly. This matches the implicit membership in the
    # primary Windows group in Active Directory.
    attr_reader :groups
    # True if the User account is disabled. Set to false to enable a disabled
    # User account. This is a boolean representation of the LDAP
    # userAccountControl attribute.
    attr :disabled, true
    # The User's first name. This corresponds to the LDAP givenName attribute
    # and is used in the LDAP displayName, description, and name attributes.
    # This defaults to the username when a User is created using User.new,
    # but is set to the correct value when a User is loaded by AD.load from the
    # AD object the Container belnogs to.
    attr :first_name, true
    # The User's middle name. This corresponds to the LDAP middleName attribute
    # and is used in the LDAP displayName and description attributes. This
    # defaults to nil when a User is created using User.new, but is set to the
    # correct value when a User is loaded by AD.load from the AD object the
    # Container belongs to.
    attr :middle_name, true
    # The User's surname (last name). This corresponds to the LDAP sn attribute
    # and is used in the LDAP displayName, description, and name attributes.
    # This defaults to nil when a User is created using User.new, but is set to
    # the correct value when a User is loaded by AD.load from the AD object the
    # Container belongs to.
    attr :surname, true
    # The User's Windows password. This defaults to nil when a User is created
    # using User.new. This does not reflect the current User's password, but
    # if it is set, the password will be changed.
    attr :password, true
    # True if the User has been removed from the Container, false otherwise.
    # This is set by the Container if the User is removed.
    attr :removed, true
    
    # The User object automatically adds itself to the Container object
    # specified. The rid should not be set directly. The rid should only be
    # set by the AD object when loading users from Active Directory. The
    # username (case-insensitive) and the rid must be unique in the AD object,
    # otherwise a RuntimeError is raised. The primary_group must be of the
    # type RADUM::GROUP_GLOBAL_SECURITY or RADUM::GROUP_UNIVERSAL_SECURITY
    # or a RuntimeError is raised.
    def initialize(username, container, primary_group, disabled = false,
                   rid = nil) # :doc:
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
      
      # The primary group must be of one of these two types. It appears you can
      # change a group's type to GROUP_DOMAIN_LOCAL_SECURITY in the AD Users and
      # Groups tool if someone has that as their primary group, but you can't
      # set a group of that type as someone's primary group. You can't change
      # the type of a group to anything that has an AD group type of
      # "Distribution" most definitely. The AD group type must be "Security"
      # for primary groups. I am just going to avoid as much confusion as
      # possible unless someone were to complain.
      unless primary_group.type == RADUM::GROUP_GLOBAL_SECURITY ||
             primary_group.type == RADUM::GROUP_UNIVERSAL_SECURITY
             raise "User primary group must be of type GROUP_GLOBAL_SECURITY" +
             " or GROUP_UNIVERSAL_SECURITY."
      end
      
      @primary_group = primary_group
      @disabled = disabled
      @rid = rid
      @distinguished_name = "cn=" + @common_name + "," + @container.name +
                            "," + @container.directory.root
      @groups = []
      @first_name = username
      @middle_name = nil
      @surname = nil
      @password = nil
      # A UNIXUser adding itself the container needs to happen at the end of
      # the initializer in that class instead because the UID value is needed.
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_user self unless instance_of? UNIXUser
      @removed = false
    end
    
    # The User's primary Windows group. This is usually the "Domain Users"
    # Windows group. Users are not members of this group directly. They are
    # members through their LDAP primaryGroupID attribute.
    def primary_group
      @primary_group
    end
    
    # Set the User's primary Windows group. The primary Windows group is
    # used by the POSIX subsystem. This is something that Windows typically
    # ignores in general, and Users are members implicitly by their LDAP
    # primaryGroupID attribute. The Group or UNIXGroup specified must be
    # of the type RADUM::GROUP_GLOBAL_SECURITY or
    # RADUM::GROUP_UNIVERSAL_SECURITY or a RuntimeError is raised. This
    # method will automatically remove membership in the Group or UNIXGroup
    # specified if necessary as Users are not members of the Group or UNIXGroup
    # directly.
    def primary_group=(group)
      unless group.type == RADUM::GROUP_GLOBAL_SECURITY ||
             group.type == RADUM::GROUP_UNIVERSAL_SECURITY
             raise "User primary group must be of type GROUP_GLOBAL_SECURITY" +
             " or GROUP_UNIVERSAL_SECURITY."
      end
      
      remove_group group
      @primary_group = group
    end
    
    # The common name (cn) portion of the LDAP distinguisedName attribute and
    # the LDAP cn attribute itself.
    def common_name
      @common_name
    end
    
    # The common_name is set to the username by default whe a User is created
    # using User.new, but it is set to the correct value when the User is
    # loaded by AD.load from the AD object the Container belongs to. The
    # username value corresponds to the LDAP sAMAccountName attribute. It is
    # possible for the LDAP cn attribute to be different than sAMAccountName
    # however, so this allows one to set the LDAP cn attribute directly. Setting
    # the common_name also changes the distinguished_name accordingly (which is
    # also built automatically).
    def common_name=(cn)
      @distinguished_name = "cn=" + cn + "," + @container.name + "," +
                            @container.directory.root
      @common_name = cn
    end
    
    # Make the User a member of the Group or UNIXGroup. This is represented
    # in the LDAP member attribute for the Group or UNIXGroup. A User is listed
    # in the Group or UNIXGroup LDAP member attribute unless it is the User's
    # primary_group. In that case, the User's membership is based solely on
    # the User's LDAP primaryGroupID attribute (which contains the RID of that
    # Group or UNIXGroup - the Group or UNIXGroup does not list the User in its
    # LDAP member attribute, hence the logic in the code). The unix_main_group
    # for UNIXUsers has the UNIXUser as a member in a similar way based on the
    # LDAP gidNumber attribute for the UNIXUser. The UNIXGroup's LDAP
    # memberUid and msSFU30PosixMember attributes do not list the UNIXUser
    # as a member if the UNIXGroup is their unix_main_group, but this module
    # makes sure UNIXUsers are also members of their unix_main_group from
    # the Windows perspective. A RuntimeError is raised if the User already
    # has this group as their primary_group or if the Group is not in the
    # same AD.
    #
    # This automatically adds the User to the Group's or UNIXGroup's list of
    # users.
    def add_group(group)
      if @container.directory == group.container.directory
        unless @primary_group == group
          @groups.push group unless @groups.include? group
          group.add_user self unless group.users.include? self
        else
          raise "User is already a member of their primary group."
        end
      else
        raise "Group must be in the same directory."
      end
    end
    
    # Remove the User membership in the Group or UNIXGroup. This automatically
    # removes the User form the Group's or UNIXGroup's list of users.
    def remove_group(group)
      @groups.delete group
      group.remove_user self if group.users.include? self
    end
    
    # Determine if a User is a member of the Group or UNIXGroup. This also
    # evaluates to true if the Group or UNIXGroup is the primary_group.
    def member_of?(group)
      @groups.include? group || @primary_group == group
    end
    
    # The String representation of the User object.
    def to_s
      "User [(" + (@disabled ? "USER_DISABLED" : "USER_ENABLED") +
      ", RID #{@rid}) #{@username} #{@distinguished_name}]"
    end
  end
  
  # The UNIXUser class represents a UNIX Windows user account. It is a subclass
  # of the User class. See the User class documentation for its attributes as
  # well.
  class UNIXUser < User
    # The UNIXUser's UNIX UID. This corresponds to the LDAP uidNumber attribute.
    attr_reader :uid
    # The UNIXUser's UNIX GID. This corresponds to the LDAP gidNumber attribute.
    # This is set by setting the UNIXUser's unix_main_group attribute with the
    # UNIXUser.unix_main_group= method.
    attr_reader :gid
    # The UNIXUser's UNIX shell. This corresponds to the LDAP loginShell
    # attribute.
    attr :shell, true
    # The UNIXUser's UNIX home directory. This corresponds to the LDAP
    # unixHomeDirectory attribute.
    attr :home_directory, true
    # The UNIXUser's UNIX NIS domain. This corresponds to the LDAP
    # msSFU30NisDomain attribute. This needs to be set even if NIS services
    # are not being used. This defaults to "radum" when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to.
    attr :nis_domain, true
    # The UNIXUser's UNIX GECOS field. This corresponds to the LDAP gecos
    # attribute. This defaults to username when a UNIXUser is created using
    # UNIXUser.new, but it is set to the correct value when the UNIXUser is
    # loaded by AD.load from the AD object the Container belongs to.
    attr :gecos, true
    # The UNIXUser's UNIX password field. This can be a crypt or MD5 value
    # (or whatever your system supports potentially - Windows works with
    # crypt and MD5 in Microsoft Identity Management for UNIX). This
    # corresponds to the LDAP unixUserPassword attribute. The unix_password
    # value defaults to "*" when a UNIXUser is created using UNIXUser.new,
    # but it is set to the correct value when the UNIXUser is loaded by
    # AD.load from the AD object the Container belongs to.
    #
    # It is not necessary to set the LDAP unixUserPassword attribute if you
    # are using Kerberos for authentication, but using LDAP (or NIS by way
    # of LDAP in Active Directory) for user information. In those cases, it
    # is best to set this field to "*", which is why that is the default.
    attr :unix_password, true
    # The UNIXUser's UNIX shadow file expire field. This is the 8th field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowExpire attribute.
    attr :shadow_expire, true
    # The UNIXUser's UNIX shadow file reserved field. This is the 9th field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowFlag attribute.
    attr :shadow_flag, true
    # The UNIXUser's UNIX shadow file inactive field. This is the 7th field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowInactive attribute.
    attr :shadow_inactive, true
    # The UNIXUser's UNIX shadow file last change field. This is the 3rd field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowLastChange attribute.
    attr :shadow_last_change, true
    # The UNIXUser's UNIX shadow file max field. This is the 5th field of
    # the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowMax attribute.
    attr :shadow_max, true
    # The UNIXUser's UNIX shadow file min field. This is the 4th field of
    # the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowMin attribute.
    attr :shadow_min, true
    # The UNIXUser's UNIX shadow file warning field. This is the 6th field of
    # the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowWarning attribute.
    attr :shadow_warning, true
    
    def initialize(username, container, primary_group, uid, unix_main_group,
                   shell, home_directory, nis_domain = "radum",
                   disabled = false, rid = nil)
      # The UID must be unique.
      if container.directory.uids.include? uid
        raise "UID is already in use in the directory."
      end
      
      super username, container, primary_group, disabled, rid
      @uid = uid
      @unix_main_group = unix_main_group
      
      if @container.directory == @unix_main_group.container.directory
        unless @unix_main_group.instance_of? UNIXGroup
          raise "UNIXUser unix_main_group must be a UNIXGroup."
        else
          @gid = @unix_main_group.gid
          @container.add_group @unix_main_group
          add_group @unix_main_group
        end
      else
        raise "UNIXUser unix_main_group must be in the same directory."
      end
      
      @shell = shell
      @home_directory = home_directory
      @nis_domain = nis_domain
      @gecos = username
      @unix_password = "*"
      @shadow_expire = nil
      @shadow_flag = nil
      @shadow_inactive = nil
      @shadow_last_change = nil
      @shadow_max = nil
      @shadow_min = nil
      @shadow_warning = nil
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_user self
      @removed = false
    end
    
    def unix_main_group
      @unix_main_group
    end
    
    def unix_main_group=(group)
      if group.instance_of? UNIXGroup
        if @container.directory == group.container.directory
          @unix_main_group = group
          @gid = group.gid
          @container.add_group group
          add_group group
        else
          raise "UNIXUser unix_main_group must be in the same directory."
        end
      else
        raise "UNIXUser unix_main_group must be a UNIXGroup."
      end
    end
    
    def to_s
      "UNIXUser [(" + (@disabled ? "USER_DISABLED" : "USER_ENABLED") +
      ", RID #{@rid}, UID #{@uid}, GID #{@unix_main_group.gid}) #{@username} " +
      "#{@distinguished_name}]"
    end
  end
  
  class Group
    attr_reader :name, :container, :type, :rid, :distinguished_name, :users
    attr_reader :groups
    attr :removed, true
    
    def initialize(name, container, type = RADUM::GROUP_GLOBAL_SECURITY,
                   rid = nil)
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
      @type = type
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
    
    # The users array this adds the user to represents the group's
    # member AD attribute. A user is listed in the group's member AD attribute
    # unless it is the user's Windows primary group. In that case, the user's
    # membership is based solely on the user's primaryGroupID attribute (which
    # contains the RID of that group - that group does not list the member in
    # its member AD attribute, hence the logic here). The unix_main_group has
    # the user as a member in a similar way based on the gidNumber AD attribute
    # for the user. The group's memberUid and msSFU30PosixMember AD attributes
    # do not list the user as a member if the group is their unix_main_group,
    # but this module makes sure UNIXUsers are also members of their
    # unix_main_group from the Windows perspective.
    def add_user(user)
      if @container.directory == user.container.directory
        unless self == user.primary_group
          @users.push user unless @users.include? user
          user.add_group self unless user.groups.include? self
        else
          raise "Group is already the User's primary_group."
        end
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
      "Group [(" + RADUM.group_type_to_s(@type) +
      ", RID #{@rid}) #{@distinguished_name}]"
    end
  end
  
  class UNIXGroup < Group
    attr_reader :gid, :nis_domain
    attr :unix_password, true
    # Note that the unix_password is generally "*" and defaults to that.
    
    def initialize(name, container, gid, type = RADUM::GROUP_GLOBAL_SECURITY,
                   nis_domain = "radum", rid = nil)
      # The GID must be unique.
      if container.directory.gids.include? gid
        raise "GID is already in use in the directory."
      end
      
      super name, container, type, rid
      @gid = gid
      @nis_domain = nis_domain
      @unix_password = "*"
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_group self
      @removed = false
    end
    
    def to_s
      "UNIXGroup [("  + RADUM.group_type_to_s(@type) + 
      ", RID #{@rid}, GID #{@gid}) #{@distinguished_name}]"
    end
  end
  
  class AD
    attr_reader :root, :domain, :server, :tls, :ldap
    attr :uids, true
    attr :gids, true
    attr :rids, true
    attr :containers, true
    
    def initialize(root, password, user = "cn=Administrator,cn=Users",
                   server = "localhost", tls = false)
      @root = root.gsub(/\s+/, "")
      @domain = @root.gsub(/dc=/, "").gsub(/,/, ".")
      @password = password
      @user = user
      @server = server
      @tls = tls
      @containers = []
      @uids = []
      @gids = []
      # RIDs are in a flat namespace, so there's no need to keep track of them
      # for user or group objects specifically, just in the directory overall.
      @rids = []

      if @tls
        port = 636
      else
        port = 389
      end
      
      @ldap = Net::LDAP.new :host => @server,
                            :port => port,
                            :auth => {
                                  :method => :simple,
                                  :username => @user + "," + @root,
                                  :password => @password
                            }
      
      @ldap.encryption :simple_tls if @tls
      
      # We add the cn=Users container by default because it is highly likely
      # that users have the Domain Users Windows group as their Windows
      # primary group. If we did not do this, there would likely be a ton
      # of warning messages in the load() method. Keep in mind that containers
      # automatically add themselves to their AD object.
      RADUM::Container.new("cn=Users", self)
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
    
    def users
      all_users = []
      
      @containers.each do |container|
        container.users.each do |user|
          all_users.push user
        end
      end
      
      all_users
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
          
          nis_domain = "radum" unless nis_domain
          rid = sid2rid_int(entry.objectSid.pop)
          
          # Note that groups add themselves to their container.
          if gid
            UNIXGroup.new(entry.name.pop, container, gid,
                          entry.groupType.pop.to_i, nis_domain, rid)
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
          disabled = entry.userAccountControl.pop.to_i == 0x202 ? true : false
          
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
    end
    
    def ==(other)
      @root.downcase == other.root.downcase
    end
    
    def eql?(other)
      self == other
    end
    
    def to_s
      "AD [#{@root} #{@server}" + (@tls ? " TLS" : "") + "]"
    end
    
    private
    
    def sid2rid_int(sid)
      sid.unpack("H2H2nNV*").pop.to_i
    end
  end
end
