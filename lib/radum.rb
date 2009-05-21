require 'rubygems'
gem 'ruby-net-ldap', '~> 0.0'
require 'net/ldap'
require 'nkf'

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
  UF_DONT_EXPIRE_PASSWD = 0x10000;
  UF_PASSWORD_EXPIRED = 0x800000;
  
  # This is a convenience method to return a String representation of a
  # Group or UNIXGroup object's type attribute, which has the value of one of
  # the RADUM group type constants.
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
    # The String represenation of the Container object's name. The name should
    # be the LDAP distinguishedName attribute without the AD root path
    # component.
    attr_reader :name
    # The AD object the Container belongs to.
    attr_reader :directory
    # An Array of User or UNIXUser objects that are in this Container.
    attr_reader :users
    # An Array of Group or UNIXGroup objects that are in this Container.
    attr_reader :groups
    # True if the Container has been removed from the AD, false
    # otherwise. This is set by the AD if the Container is removed.
    attr_accessor :removed
    
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
    # Group or UNIXGroup object's removed attribute to true. A Group or
    # UNIXGroup cannot be removed if it is still any User object's primary
    # Windows group. A UNIXGroup cannot be removed if it is any User object's
    # main UNIX group. In both cases, a RuntimeError will be raised.
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
    # The User or UNIXUser object username. This corresponds to the LDAP
    # sAMAccountName and msSFU30Name attributes. This is also used for part of
    # the LDAP userPrincipalName attribute. This does not contain any LDAP path
    # components, unlike the Container objet's name attribute (because
    # Containers can be different types of objects, like a cn=name or ou=name).
    attr_reader :username
    # The Container object the User or UNIXUser belongs to.
    attr_reader :container
    # The RID of the User or UNIXUser object. This corresponds to part of the
    # LDAP objectSid attribute. This is set when the User or UNIXUser is loaded
    # by AD.load from the AD object the Container belogs to. This attribute
    # should not be specified in the User.new method when creating a new User
    # or UNIXUser by hand.
    attr_reader :rid
    # The LDAP distinguishedName attribute for this User or UNIXUser. This can
    # be modified by setting the common name using the User.common_name= method.
    attr_reader :distinguished_name
    # The Group or UNIXGroup objects the User or UNIXUser is a member of. Users
    # and UNIXUsers are logical members of their primary_group as well, but that
    # is not added to the groups array directly. This matches the implicit
    # membership in the primary Windows group in Active Directory.
    attr_reader :groups
    # True if the User or UNIXUser has been modified. This is true for manually
    # created User or UNIXUser objects and false for initially loaded User and
    # UNIXUser objects.
    attr_reader :modified
    # True if the User or UNIXUser has been removed from the Container, false
    # otherwise. This is set by the Container if the User or UNIXUser is
    # removed.
    attr_accessor :removed
    
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
      @modified = true
      @loaded = false
    end
    
    # True if the User or UNIXUser account is disabled, false otherwise.
    # This is a boolean representation of the LDAP userAccountControl attribute.
    def disabled?
      @disabled
    end
    
    # Disable a User or UNIXUser account.
    def disable
      unless @disabled
        @disabled = true
        @modified = true
      end
    end
    
    # Enable a User or UNIXUser account.
    def enable
      if @disabled
        @disabled = false
        @modified = true
      end
    end
    
    # The User or UNIXUser first name.
    def first_name
      @first_name
    end
    
    # Set the User or UNIXUser first name. This corresponds to the LDAP
    # givenName attribute and is used in the LDAP displayName, description,
    # and name attributes. This defaults to the username when a User or
    # UNIXUser is created using User.new or UNIXUser.new, but is set to the
    # correct value when a User or UNIXUser is loaded by AD.load from the AD
    # object the Container belongs to.
    def first_name=(first_name)
      @fisrt_name = first_name
      @modified = true
    end
    
    # The User or UNIXUser middle name.
    def middle_name
      @middle_name
    end
    
    # Set the User or UNIXUser middle name. This corresponds to the LDAP
    # middleName attribute and is used in the LDAP displayName and description
    # attributes. This defaults to nil when a User or UNIXUser is created using
    # User.new or UNIXUser.new, but is set to the correct value when a User or
    # UNIXUser is loaded by AD.load from the AD object the Container belongs to.
    def middle_name=(middle_name)
      @middle_name = middle_name
      @modified = true
    end
    
    # The User or UNIXUser surname (last name).
    def surname
      @surname
    end
    
    # Set the User or UNIXUser surname (last name). This corresponds to the
    # LDAP sn attribute and is used in the LDAP displayName, description, and
    # name attributes. This defaults to nil when a User or UNIXUser is created
    # using User.new or UNIXUser.new, but is set to the correct value when a
    # User or UNIXUser is loaded by AD.load from the AD object the Container
    # belongs to.
    def surname=(surname)
      @surname = surname
      @modified = true
    end
    
    # The User or UNIXUser Windows password.
    def password
      @password
    end
    
    # Set the User or UNIXUser Windows password. This defaults to nil when a
    # User or UNIXUser is created using User.new or UNIXUser.new. This does not
    # reflect the current User or UNIXUser password, but if it is set, the
    # password will be changed.
    def password=(password)
      @password = password
      @modified = true
    end
    
    # The User primary Windows group. This is usually the "Domain Users"
    # Windows group. Users are not members of this group directly. They are
    # members through their LDAP primaryGroupID attribute.
    def primary_group
      @primary_group
    end
    
    # Set the User or UNIXUser primary Windows group. The primary Windows group
    # is used by the POSIX subsystem. This is something that Windows typically
    # ignores in general, and Users or UNIXUsers are members implicitly by
    # their LDAP primaryGroupID attribute. The Group or UNIXGroup specified
    # must be of the type RADUM::GROUP_GLOBAL_SECURITY or
    # RADUM::GROUP_UNIVERSAL_SECURITY or a RuntimeError is raised. This
    # method will automatically remove membership in the Group or UNIXGroup
    # specified if necessary as Users or UNIXUsers are not members of the Group
    # or UNIXGroup directly. The Group or UNIXGroup specified must be in the
    # same AD object or a RuntimeError is raised.
    def primary_group=(group)
      unless @container.directory == group.container.directory
        raise "Group must be in the same directory."
      end
      
      unless group.type == RADUM::GROUP_GLOBAL_SECURITY ||
             group.type == RADUM::GROUP_UNIVERSAL_SECURITY
             raise "User primary group must be of type GROUP_GLOBAL_SECURITY" +
             " or GROUP_UNIVERSAL_SECURITY."
      end
      
      remove_group group
      @primary_group = group
      @modified = true
    end
    
    # The common name (cn) portion of the LDAP distinguisedName attribute and
    # the LDAP cn attribute itself.
    def common_name
      @common_name
    end
    
    # The common_name is set to the username by default whe a User or UNIXUser
    # is created using User.new or UNIXUser.new, but it is set to the correct
    # value when the User or UNIXUser is loaded by AD.load from the AD object
    # the Container belongs to. The username value corresponds to the LDAP
    # sAMAccountName and and msSFU30Name attributes. It is possible for the
    # LDAP cn attribute to be different than sAMAccountName and msSFU30Name
    # however, so this allows one to set the LDAP cn attribute directly.
    # Setting the common_name also changes the distinguished_name accordingly
    # (which is also built automatically).
    def common_name=(cn)
      @distinguished_name = "cn=" + cn + "," + @container.name + "," +
                            @container.directory.root
      @common_name = cn
      @modified = true
    end
    
    # Make the User or UNIXUser a member of the Group or UNIXGroup. This is
    # represented in the LDAP member attribute for the Group or UNIXGroup. A
    # User or UNIXUser is listed in the Group or UNIXGroup LDAP member attribute
    # unless it is the User or UNIXUser object's primary_group. In that case,
    # the User or UNIXUser object's membership is based solely on the User or
    # UNIXUser object's LDAP primaryGroupID attribute (which contains the RID
    # of that Group or UNIXGroup - the Group or UNIXGroup does not list the
    # User or UNIXUser in its LDAP member attribute, hence the logic in the
    # code). The unix_main_group for UNIXUsers has the UNIXUser as a member in
    # a similar way based on the LDAP gidNumber attribute for the UNIXUser. The
    # UNIXGroup object's LDAP memberUid and msSFU30PosixMember attributes do
    # not list the UNIXUser as a member if the UNIXGroup is their
    # unix_main_group, but this module makes sure UNIXUsers are also members of
    # their unix_main_group from the Windows perspective. A RuntimeError is
    # raised if the User or UNIXUser already has this Group or UNIXGroup as
    # their primary_group or if the Group or UNIXGroup is not in the same AD
    # object.
    #
    # This automatically adds the User or UNIXUser to the Group or UNIXGroup
    # object's list of users.
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
    
    # Remove the User or UNIXUser membership in the Group or UNIXGroup. This
    # automatically removes the User or UNIXUser from the Group or UNIXGroup
    # object's list of users.
    def remove_group(group)
      @groups.delete group
      group.remove_user self if group.users.include? self
    end
    
    # Determine if a User or UNIXUser is a member of the Group or UNIXGroup.
    # This also evaluates to true if the Group or UNIXGroup is the
    # User or UNIXUser object's primary_group.
    def member_of?(group)
      @groups.include? group || @primary_group == group
    end
    
    # Set the loaded flag. Calling this only has an effect once. This is only
    # callled by AD.load when a User or UNIXUser is initially loaded.
    def loaded
      # This allows the modified attribute to be hidden.
      unless @loaded
        @loaded = true
        @modified = false
      end
    end
    
    # Check if the User or UNIXUser was loaded from Active Directory.
    def loaded?
      @loaded
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
    # The UNIXUser UNIX UID. This corresponds to the LDAP uidNumber attribute.
    attr_reader :uid
    # The UNIXUser UNIX GID. This corresponds to the LDAP gidNumber attribute.
    # This is set by setting the UNIXUser unix_main_group attribute with the
    # UNIXUser.unix_main_group= method.
    attr_reader :gid
    
    # The UNIXUser object automatically adds itself to the Container object
    # specified. The rid should not be set directly. The rid should only be
    # set by the AD object when loading users from Active Directory. The
    # username (case-insensitive), rid, and uid must be unique in the AD
    # object, otherwise a RuntimeError is raised. The primary_group must be of
    # the type RADUM::GROUP_GLOBAL_SECURITY or RADUM::GROUP_UNIVERSAL_SECURITY
    # or a RuntimeError is raised. The unix_main_group must be an instance of
    # UNIXGroup or a RuntimeError is raised.
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
    
    # The UNIXUser UNIX shell.
    def shell
      @shell
    end
    
    # Set the UNIXUser UNIX shell. This corresponds to the LDAP loginShell
    # attribute.
    def shell=(shell)
      @shell = shell
      @modified = true
    end
    
    # The UNIXUser UNIX home directory.
    def home_directory
      @home_directory
    end
    
    # Set the UNIXUser UNIX home directory. This corresponds to the LDAP
    # unixHomeDirectory attribute.
    def home_directory=(home_directory)
      @home_directory = home_directory
      @modified = true
    end
    
    # The UNIXUser UNIX NIS domain.
    def nis_domain
      @nis_domain
    end
    
    # Set the UNIXUser UNIX NIS domain. This corresponds to the LDAP
    # msSFU30NisDomain attribute. This needs to be set even if NIS services
    # are not being used. This defaults to "radum" when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to.
    def nis_domain=(nis_domain)
      @nis_domain = nis_domain
      @modified = true
    end
    
    # The UNIXUser UNIX GECOS field.
    def gecos
      @gecos
    end
    
    # Set the UNIXUser UNIX GECOS field. This corresponds to the LDAP gecos
    # attribute. This defaults to username when a UNIXUser is created using
    # UNIXUser.new, but it is set to the correct value when the UNIXUser is
    # loaded by AD.load from the AD object the Container belongs to.
    def gecos=(gecos)
      @gecos = gecos
      @modified = true
    end
    
    # The UNIXUser UNIX password field.
    def unix_password
      @unix_password
    end
    
    # Set the UNIXUser UNIX password field. This can be a crypt or MD5 value
    # (or whatever your system supports potentially - Windows works with
    # crypt and MD5 in Microsoft Identity Management for UNIX). This
    # corresponds to the LDAP unixUserPassword attribute. The unix_password
    # value defaults to "*" when a UNIXUser is created using UNIXUser.new,
    # but it is set to the correct value when the UNIXUser is loaded by
    # AD.load from the AD object the Container belongs to.
    #
    # It is not necessary to set the LDAP unixUserPassword attribute if you
    # are using Kerberos for authentication, but using LDAP (or NIS by way of
    # LDAP in Active Directory) for user information. In those cases, it is
    # best to set this field to "*", which is why that is the default.
    def unix_password=(unix_password)
      @unix_password = unix_password
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file expire field.
    def shadow_expire
      @shadow_expire
    end
    
    # Set the UNIXUser UNIX shadow file expire field. This is the 8th field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowExpire attribute.
    def shadow_expire=(shadow_expire)
      @shadow_expire = shadow_expire
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file reserved field.
    def shadow_flag
      @shadow_flag
    end
    
    # Set the UNIXUser UNIX shadow file reserved field. This is the 9th field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowFlag attribute.
    def shadow_flag=(shadow_flag)
      @shadow_flag = shadow_flag
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file inactive field.
    def shadow_inactive
      @shadow_inactive
    end
    
    # Set the UNIXUser UNIX shadow file inactive field. This is the 7th field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowInactive attribute.
    def shadow_inactive=(shadow_inactive)
      @shadow_inactive = shadow_inactive
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file last change field.
    def shadow_last_change
      @shadow_last_change
    end
    
    # Set the UNIXUser UNIX shadow file last change field. This is the 3rd field
    # of the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowLastChange attribute.
    def shadow_last_change=(shadow_last_change)
      @shadow_last_change = shadow_last_change
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file max field.
    def shadow_max
      @shadow_max
    end
    
    # Set the UNIXUser UNIX shadow file max field. This is the 5th field of
    # the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowMax attribute.
    def shadow_max=(shadow_max)
      @shadow_max = shadow_max
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file min field.
    def shadow_min
      @shadow_min
    end
    
    # Set the UNIXUser UNIX shadow file min field. This is the 4th field of
    # the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowMin attribute.
    def shadow_min=(shadow_min)
      @shadow_min = shadow_min
      @modified = true
    end
    
    # The UNIXUser UNIX shadow file warning field.
    def shadow_warning
      @shadow_warning
    end
    
    # Set the UNIXUser UNIX shadow file warning field. This is the 6th field of
    # the /etc/shadow file. This defaults to nil when a UNIXUser is created
    # using UNIXUser.new, but it is set to the correct value when the UNIXUser
    # is loaded by AD.load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowWarning attribute.
    def shadow_warning=(shadow_warning)
      @shadow_warning = shadow_warning
      @modified = true
    end
    
    # The UNIXUser UNIX main group. This is where the UNIXUser UNIX GID
    # value comes from, which is reflected in the gid attribute.
    def unix_main_group
      @unix_main_group
    end
    
    # Set the UNIXUser UNIX main group. This also sets the UNIXUser gid
    # attribute. The group must be of the type UNIXGroup and in the same AD
    # object or a RuntimeError is raised. This method does not automatically
    # remove membership in the previous unix_main_group UNIXGroup.
    def unix_main_group=(group)
      if group.instance_of? UNIXGroup
        if @container.directory == group.container.directory
          @unix_main_group = group
          @gid = group.gid
          @container.add_group group
          add_group group
          @modified = true
        else
          raise "UNIXUser unix_main_group must be in the same directory."
        end
      else
        raise "UNIXUser unix_main_group must be a UNIXGroup."
      end
    end
    
    # The String representation of the UNIXUser object.
    def to_s
      "UNIXUser [(" + (@disabled ? "USER_DISABLED" : "USER_ENABLED") +
      ", RID #{@rid}, UID #{@uid}, GID #{@unix_main_group.gid}) #{@username} " +
      "#{@distinguished_name}]"
    end
  end
  
  # The Group class represents a standard Windows group.
  class Group
    # The String representation of the Group or UNIXGroup name. This is similar
    # to a User or UNIXUser username in that it does not contain any LDAP path
    # components. This corresponds to the LDAP cn, msSFU30Name, name, and
    # sAMAccountName attributes.
    attr_reader :name
    # The Container object the Group or UNIXGroup belongs to.
    attr_reader :container
    # The RADUM group type of the Group or UNIXGroup. This corresponds to the
    # LDAP groupType attribute. This defaults to RADUM::GROUP_GLOBAL_SECURITY
    # when a Group or UNIXGroup is created using Group.new or UNIXGroup.new,
    # but it is set to the correct value when a Group or UNIXGroup is loaded by
    # AD.load from the AD object the Container belongs to.
    attr_reader :type
    # The RID of the Group or UNIXGroup object. This correponds to part of the
    # LDAP objectSid attribute. This is set when the Group or UNIXGroup is
    # loaded by AD.load from the AD object the Container belongs to. This
    # attribute should not be specified in the Group.new or UNIXGroup.new
    # methods when creating a new Group or UNIXGroup by hand.
    attr_reader :rid
    # The LDAP distinguishedName attribute for this Group or UNIXGroup.
    attr_reader :distinguished_name
    # The User or UNIXUser objects that are members of the Group or UNIXGroup.
    # Users or UNIXUsers are not members of the Group or UNIXGroup if the Group
    # or UNIXGroup is their primary Windows group in Active Directory.
    attr_reader :users
    # The Group or UNIXGroup objects that are members of the Group or UNIXGroup.
    attr_reader :groups
    # True if the Group or UNIXGroup has been modified. This is true for
    # manually created Group or UNIXGroup objects and false for initially
    # loaded Group and UNIXGroup objects.
    attr_reader :modified
    # True if the Group or UNIXGroup has been removed from the Container, false
    # otherwise. This is set by the Container if the Group is removed.
    attr_accessor :removed
    
    # The Group object automatically adds itself to the Container object
    # specified. The rid should not be set directly. The rid should only be
    # set by the AD object when loading groups from Active Directory. The name
    # (case-insensitive) and the rid must be unique in the AD object, otherwise
    # a RuntimeError is raised. The type must be one of the RADUM group type
    # constants.
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
      @modified = true
      @loaded = false
    end
    
    # Make the User or UNIXUser a member of the Group or UNIXGroup. This
    # represents the LDAP member attribute for the Group or UNIXGroup. A User
    # or UNIXUser is listed in the Group or UNIXGroup object's LDAP member
    # attribute unless it is their primary_group. In that case, the User or
    # UNIXUser object's LDAP primaryGroupID attribute is used (which contains
    # the RID of that Group or UNIXGroup - the Group or UNIXGroup does not list
    # the User or UNIXUser in its LDAP member attribute, hence the logic in the
    # code). The unix_main_group for UNIXUsers has the UNIXUser as a member in a
    # similar way based on the LDAP gidNumber attribute for the UNIXUser. The
    # UNIXGroup object's LDAP memberUid and msSFU30PosixMember attributes do
    # not list the UNIXUser as a member of the UNIXGroup is their
    # unix_main_group, but this module makes sure the UNIXUsers are also
    # members of their unix_main_group from the Windows perspective. A
    # RuntimeError is raised if the User or UNIXUser already has this Group or
    # UNIXGroup as their primary_group or if the Group or UNIXGroup is not in
    # the same AD object.
    #
    # This automatically adds the Group or UNIXGroup to the User or UNIXUser
    # object's list of groups.
    def add_user(user)
      if @container.directory == user.container.directory
        unless self == user.primary_group
          @users.push user unless @users.include? user
          user.add_group self unless user.groups.include? self
          @modified = true
        else
          raise "Group is already the User's primary_group."
        end
      else
        raise "User must be in the same directory."
      end
    end
    
    # Remove the User or UNIXUser membership in the Group or UNIXGroup. This
    # automatically removes the Group or UNIXGroup from the User or UNIXUser
    # object's list of groups.
    def remove_user(user)
      @users.delete user
      user.remove_group self if user.groups.include? self
      @modified = true
    end
    
    # Determine if the Group or UNIXGroup is a member of the Group or UNIXGroup.
    def member_of?(group)
      @groups.include? group
    end
    
    # Make the Group or UNIXGroup a member of the Group or UNIXGroup. This
    # represents the LDAP member attribute for the Group or UNIXGroup. A
    # RuntimeError is raised if the Group or UNIXGroup is the same as the
    # current Group or UNIXGroup (cannot be a member of itself) or the Group
    # or UNIXGroup is not in the same AD object.
    def add_group(group)
      unless @container.directory == group.container.directory
        raise "Group must be in the same directory."
      end
      
      if self == group
        raise "A group cannot have itself as a member."
      end
      
      @groups.push group unless @groups.include? group
      @modified = true
    end
    
    # Remove the Group or UNIXGroup membership in the Group or UNIXGroup.
    def remove_group(group)
      @groups.delete group
      @modified = true
    end
    
    # Set the loaded flag. Calling this only has an effect once. This is only
    # callled by AD.load when a Group or UNIXGroup is initially loaded.
    def loaded
      # This allows the modified attribute to be hidden.
      unless @loaded
        @loaded = true
        @modified = false
      end
    end
    
    # Check if the Group or UNIXGroup was loaded from Active Directory.
    def loaded?
      @loaded
    end
    
    # The String representation of the Group object.
    def to_s
      "Group [(" + RADUM.group_type_to_s(@type) +
      ", RID #{@rid}) #{@distinguished_name}]"
    end
  end
  
  # The UNIXGroup class represents a UNIX Windows group. It is a subclass of
  # the Group class. See the Group class documentation for its attributes as
  # well.
  class UNIXGroup < Group
    # The UNIXGroup UNIX GID. This corresponds to the LDAP gidNumber
    # attribute.
    attr_reader :gid
    
    # The UNIXGroup object automatically adds itself to the Container object
    # specified. The rid shold not be set directly. The rid should only be
    # set by the AD object when loading groups from Active Directory. The name
    # (case-insensitive), rid, and gid must be unique in the AD object,
    # otherwise a RuntimeError is raised. The type must be one of the RADUM
    # group type constants.
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
    
    # The UNIXGroup UNIX NIS domain.
    def nis_domain
      @nis_domain
    end
    
    # Set the UNIXGroup UNIX NIS domain. This corresponds to the LDAP
    # msSFU30NisDomain attribute. This needs to be set even if NIS services
    # are not being used. This defaults to "radum" when a UNIXGroup is created
    # using UNIXGroup.new, but it is set to the correct value when the UNIXGroup
    # is loaded by AD.load from the AD object the Container belongs to.
    def nis_domain=(nis_domain)
      @nis_domain = nis_domain
      @modified = true
    end
    
    # The UNIXGroup UNIX password field.
    def unix_password
      @unix_password
    end
    
    # Set the UNIXGroup UNIX password field. This can be a crypt or MD5 value
    # (or whatever your system supports potentially - Windows works with crypt
    # and MD5 in Microsoft Identity Management for UNIX). This corresponds to
    # the LDAP unixUserPassword attribute. The unix_password value defaults
    # to "*" when a UNIXGroup is created using UNIXGroup.new, but it is set
    # to the correct value when the UNIXGroup is loaded by AD.load from the AD
    # object the Container belongs to.
    #
    # It is not necessary to set the LDAP unixUserPassword attribute if you
    # are using Kerberos for authentication, but using LDAP (or NIS by way of
    # LDAP in Active Directory) for user information. In that case, it is best
    # to set this field to "*", which is why that is the default. Additionally,
    # most of the time UNIX groups do not have a password.
    def unix_password=(unix_password)
      @unix_password = unix_password
      @modified = true
    end
    
    # The String representation of the UNIXGroup object.
    def to_s
      "UNIXGroup [("  + RADUM.group_type_to_s(@type) + 
      ", RID #{@rid}, GID #{@gid}) #{@distinguished_name}]"
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
    # True if using TLS, otherwise false. This defaults to false when an AD
    # is created using AD.new.
    attr_reader :tls
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
    # The tls paramemter is a boolen indicating if TLS should be used for the
    # connection. It defaults to false. If TLS is specified, the connection
    # port will be set to 636, otherwise the port will be set to 389. It is
    # possible to change the port for nonstandard configurations after the
    # AD object is created using the AD.port= method. It is not possible to
    # change the TLS communication flag after AD creation. An example of
    # creating an AD object follows:
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
        @port = 636
      else
        @port = 389
      end
      
      @ldap = Net::LDAP.new :host => @server,
                            :port => @port,
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
    
    # The port number used to communicate with the Active Directory server.
    def port
      @port
    end
    
    # Set the port number used to communicate with the Active Directory server.
    # This defaults to 389 for non-TLS and 636 for TLS, but can be set here for
    # nonstandard configurations.
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
      "AD [#{@root} #{@server}" + (@tls ? " TLS" : "") + "]"
    end
    
    private
    
    # Unpack a RID from the SID value in the LDAP objectSid attribute for a
    # user or group in Active Directory.
    def sid2rid_int(sid)
      sid.unpack("H2H2nNV*").pop.to_i
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
          
          @ldap.add(:dn => group.distinguished_name, :attributes => attr)
          
          unless @ldap.get_operation_result.code == 0
            puts "SYNC ERROR: " + @ldap.get_operation_result.message
          end
        else
          puts "SYNC WARNING: #{group.name} already exist. Not created."
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
            #:badPasswordTime => 0.to_s,
            #:badPwdCount => 0.to_s,
            #:codePage => 0.to_s,
            #:countryCode => 0.to_s,
            #:dSCorePropagationData => 0.to_s,
            #:instanceType => 4.to_s,
            #:distinguishedName => user.distinguished_name,
            # All users are of the objectclasses "top", "person",
            # "orgainizationalPerson", and "user".
            :objectclass => [ "top", "person", "organizationalPerson", "user" ],
            #:primaryGroupID => rid.to_s,
            #:pwdLastSet => 128872710726572500.to_s,
            :sAMAccountName => user.username,
            #:sAMAccountType => 805306368.to_s,
            :userAccountControl => (UF_NORMAL_ACCOUNT + UF_PASSWD_NOTREQD +
                                    UF_PASSWORD_EXPIRED +
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
            #:userPrincipalName => realm,
            #:userPassword => "n3wU$3R@1"
            #:unicodePwd => NKF.nkf('-w16m0', '"n3wU$3R@1"'),
            #:pwdLastSet => 0.to_s,
            #:lockoutTime => 0.to_s
          })
          
          #attr.merge!({
          #  :msSFU30Name => user.username,
          #  :msSFU30NisDomain => user.nis_domain,
          #  :unixUserPassword => user.unix_password
          #}) if user.instance_of? UNIXUser
          
          puts attr.to_yaml
          puts user.distinguished_name
          @ldap.add(:dn => user.distinguished_name, :attributes => attr)
          
          unless @ldap.get_operation_result.code == 0
            puts "SYNC ERROR: " + @ldap.get_operation_result.message
            puts "  Error code: " + @ldap.get_operation_result.code.to_s
          end
        else
          puts "SYNC WARNING: #{user.username} already exists. Not created."
        end
      end
    end
  end
end
