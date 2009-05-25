module RADUM
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
    # True if the User or UNIXUser has been removed from the Container, false
    # otherwise. This is set by the Container if the User or UNIXUser is
    # removed.
    attr_accessor :removed
    
    # The User object automatically adds itself to the Container object
    # specified. The rid should not be set directly. The rid should only be
    # set by the AD object when loading users from Active Directory. The
    # username (case-insensitive) and the rid must be unique in the AD object,
    # otherwise a RuntimeError is raised. The primary_group must be of the
    # RADUM group type GROUP_GLOBAL_SECURITY or GROUP_UNIVERSAL_SECURITY
    # or a RuntimeError is raised. Note that a User will not be forced to change
    # their Windows password on their first login unless this is changed by
    # calling the toggle_must_change_password method. If no password is set
    # for the User, a random password will be generated. The random password
    # will probably meet Group Policy password security requirements, but it
    # is suggested that a password be set to ensure this is the case, otherwise
    # setting the User password during Active Directory creation might fail,
    # which results in a disabled user account that has no password.
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
      unless primary_group.type == GROUP_GLOBAL_SECURITY ||
             primary_group.type == GROUP_UNIVERSAL_SECURITY
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
      @must_change_password = false
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
    
    # The User or UNIXUser Windows password. This is only set to a value other
    # than nil if the password should be changed on the next AD.sync call. Once
    # the User or UNIXUser is synchronized with Active Directory, the password
    # attribute is set to nil again. This is because the password attribute does
    # not actually reflect the current Active Directory user password, which
    # cannot be read through LDAP directly.
    def password
      @password
    end
    
    # Set the User or UNIXUser Windows password. This defaults to nil when a
    # User or UNIXUser is created using User.new or UNIXUser.new. This does not
    # reflect the current User or UNIXUser password, but if it is set, the
    # password will be changed. Once the User or UNIXUser is synchronized with
    # Active Directory using AD.sync, the password attribute is set to nil
    # again. This is because the password attribute does not actually reflect
    # the current Active Directory user password, which cannot be read through
    # LDAP directly.
    def password=(password)
      @password = password
      @modified = true
    end
    
    # Check if the User or UNIXUser has to change their Windows password on
    # their first login. Returns true if this is the case, false otherwise.
    # This defaults to false when User or UNIXUser objects are created.
    def must_change_password?
      @must_change_password
    end
    
    # Force the User or UNIXUser to change their password on their next
    # login. Note that the default value is to not force a password change on
    # the next login.
    def force_change_password
      @must_change_password = true
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
    # must be of the RADUM group type GROUP_GLOBAL_SECURITY or
    # GROUP_UNIVERSAL_SECURITY or a RuntimeError is raised. This method will
    # automatically remove membership in the Group or UNIXGroup specified
    # if necessary as Users or UNIXUsers are not members of the Group or
    # UNIXGroup directly. The Group or UNIXGroup specified must be in the
    # same AD object or a RuntimeError is raised.
    def primary_group=(group)
      unless @container.directory == group.container.directory
        raise "Group must be in the same directory."
      end
      
      unless group.type == GROUP_GLOBAL_SECURITY ||
             group.type == GROUP_UNIVERSAL_SECURITY
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
    def set_loaded
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
    
    # True if the User or UNIXUser has been modified. This is true for manually
    # created User or UNIXUser objects and false for initially loaded User and
    # UNIXUser objects.
    def modified?
      @modified
    end
    
    # Set the RID only if it has not already been set. This is used by the AD
    # class when doing synchronization. Once there is a RID value, it can be
    # set. This is not meant for general use. It will only set the rid attribute
    # if it has not already been set.
    def set_rid(rid)
      if @rid.nil?
        @rid = rid
        @container.directory.rids.push rid
      end
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
    # the RADUM group type GROUP_GLOBAL_SECURITY or GROUP_UNIVERSAL_SECURITY
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
end
