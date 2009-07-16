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
    # by AD#load from the AD object the Container belogs to. This attribute
    # should not be specified in the User.new method when creating a new User
    # or UNIXUser by hand.
    attr_reader :rid
    # The LDAP distinguishedName attribute for this User or UNIXUser.
    attr_reader :distinguished_name
    # The Group or UNIXGroup objects the User or UNIXUser is a member of. Users
    # and UNIXUsers are logical members of their primary_group as well, but that
    # is not added to the groups array directly. This matches the implicit
    # membership in the primary Windows group in Active Directory.
    attr_reader :groups
    # An array of Group or UNIXGroup objects removed from the User or
    # UNIXUser.
    attr_reader :removed_groups
    # True if the User or UNIXUser has been removed from the Container, false
    # otherwise. This is set by the Container if the User or UNIXUser is
    # removed.
    attr_accessor :removed
    
    # Create a new User object that represents a Windows user in Active
    # Directory. This method takes a Hash containing arguments, some of which
    # are required and others optional. The supported arguments follow:
    #
    # * :username => The User object's username [required]
    # * :container => The User object's associated Container [required]
    # * :primary_group => The User object's primary Windows group [required]
    # * :disabled => User object disabled flag [default false]
    # * :rid => The RID of the User object [optional]
    #
    # The :username argument (case-insensitive) and the :rid argument must be
    # unique in the AD object, otherwise a RuntimeError is raised. The
    # :primary_group argument must be of the RADUM type GROUP_GLOBAL_SECURITY
    # or GROUP_UNIVERSAL_SECURITY, otherwise a RuntimeError is raised. The
    # :disabled argument indicates if the User object should be disabled, and
    # it defaults to false. The :rid argument should not be set directly except
    # from the AD#load method itself. The User object automatically adds itself
    # to the Container object specified by the :container argument. The
    # argument types required follow:
    #
    # * :username [String]
    # * :container [Container]
    # * :primary_group [Group or UNIXGroup]
    # * :disabled [boolean]
    # * :rid [integer]
    #
    # Note that a User will not be forced to change their Windows password on
    # their first login unless this is changed by calling the
    # toggle_must_change_password method. If no password is set for the User,
    # a random password will be generated. The random password will probably
    # meet Group Policy password security requirements, but it is suggested
    # that a password be set to ensure this is the case, otherwise setting the
    # User password during Active Directory creation might fail, which results
    # in a disabled Active Directory user account that has no password.
    #
    # See the documentation for each attribute method for what the default
    # values of each attribute is based on calling this method.
    def initialize(args = {})
      @rid = args[:rid] || nil
      @container = args[:container] or raise "User :container argument" +
                                             " required."
      
      # The RID must be unique.
      if @container.directory.rids.include? @rid
        raise "RID #{rid} is already in use in the directory."
      end
      
      @username = args[:username] or raise "User :username argument required."
      
      # The username (sAMAccountName) must be unique (case-insensitive). This
      # is needed in case someone tries to make the same username in two
      # different containers.
      if @container.directory.find_user_by_username @username
        raise "User is already in the directory."
      end
      
      @primary_group = args[:primary_group] or raise "User :primary_group" +
                                                     "argument required."
      
      # The primary group must be of one of these two types. It appears you can
      # change a group's type to GROUP_DOMAIN_LOCAL_SECURITY in the AD Users and
      # Groups tool if someone has that as their primary group, but you can't
      # set a group of that type as someone's primary group. You can't change
      # the type of a group to anything that has an AD group type of
      # "Distribution" most definitely. The AD group type must be "Security"
      # for primary groups. I am just going to avoid as much confusion as
      # possible unless someone were to complain.
      unless @primary_group.type == GROUP_GLOBAL_SECURITY ||
             @primary_group.type == GROUP_UNIVERSAL_SECURITY
             raise "User primary group must be of type GROUP_GLOBAL_SECURITY" +
             " or GROUP_UNIVERSAL_SECURITY."
      end
      
      @disabled = args[:disabled] || false
      @distinguished_name = "cn=" + @username + "," + @container.name +
                            "," + @container.directory.root
      @groups = []
      @removed_groups = []
      @first_name = @username
      @middle_name = nil
      @surname = nil
      # These are attributes of the Profile tab in Active Directory Users and
      # Computers.
      @script_path = nil
      @profile_path = nil
      # The local_path variable is set alone if it represents the "Local
      # path" part of the Home folder section of the Profile tab. In this
      # case, local_drive should be left nil. If it is used to represent the
      # "Connect" part of the Home folder section of the Profile tab,
      # local_path and local_drive should both be set. Note that these
      # two options in the Home folder section of the Profile tab are mutually
      # exclusive. This is enforced in the setter methods. Also note these
      # variables represent the following LDAP attributes:
      #
      # local_path  --> homeDirectory
      # local_drive --> homeDrive
      #
      # I am using these names because there is a home_directory instance
      # variable to represent UNIX home directories, and the way these are
      # set with the methods defined in this class better reflect the Active
      # Directory Users and Computers tool.
      @local_path = nil
      @local_drive = nil
      # Password related instance variables. The password itself is not
      # reflected here unless we are trying to change it to a new value
      # (otherwise it is just nil).
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
    # correct value when a User or UNIXUser is loaded by AD#load from the AD
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
    # UNIXUser is loaded by AD#load from the AD object the Container belongs to.
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
    # User or UNIXUser is loaded by AD#load from the AD object the Container
    # belongs to.
    def surname=(surname)
      @surname = surname
      @modified = true
    end
    
    # The path to the User or UNIXUser object's logon script.
    def script_path
      @script_path
    end
    
    # Set the User or UNIXUser logon script path. This corresponds to the
    # LDAP scriptPath attribute and is the "Logon script" setting in the
    # Profile tab of the Active Directory Users and Computers tool.
    def script_path=(script_path)
      @script_path = script_path
      @modified = true
    end
    
    # The path to the User or UNIXUser object's Windows profile.
    def profile_path
      @profile_path
    end
    
    # Set the User or UNIXUser profile path. This corresponds to the LDAP
    # profilePath attribute and is the "Profile path" setting in the Profile
    # tab of the Active Directory Users and Computers tool.
    def profile_path=(profile_path)
      @profile_path = profile_path
      @modified = true
    end
    
    # The "Local path" represented in the Active Directory Users and Computers
    # Profile tab Home folder section. This also represents the path value
    # used in the User#connect_drive_to method and is used in conjunction with
    # User#local_drive in the case User#connect_drive_to was called instead of
    # simply calling the User#local_path= method.
    def local_path
      @local_path
    end
    
    # Set the User or UNIXUser "Local path" in the Active Directory Users and
    # Computers Profile tab Home folder section. One can either set the "Local
    # path" or set the "Connect ... To" part of the Home folder section. This
    # sets the LDAP homeDirectory attribute only. If you want to connect a drive
    # to a path for the Home folder, use then User#connect_drive_to method
    # instead. Note that this method makes sure that the homeDrive LDAP
    # attribute is not set to enforce the proper behavior on the LDAP side.
    def local_path=(path)
      @local_drive = nil
      @local_path = path
      @modified = true
    end
    
    # The drive used in the User#connect_drive_to method when setting the
    # "Connect ... To" Home folder section of the Active Directory Users
    # and Computers Profile tab section. This value should be used in
    # conjunction with the User#local_path value if the User#connect_drive_to
    # method was called.
    def local_drive
      @local_drive
    end
    
    # Set the User or UNIXUser "Connect ... To" in the Active Directory Users
    # and Computers Profile tab Home folder section. One can either set the
    # "Connect ... To" or set the "Local path" part of the Home folder section.
    # This sets the LDAP homeDrive and homeDirectory attributes. If you want to
    # simply set a "Local path" for the Home folder, use the User#local_path=
    # method instead.
    #
    # As an example, to connect drive Z: to \\\\server\\share, do the following
    # on a User or UNIXUser object named user:
    #
    #  user.connect_drive_to "Z:", "\\\\server\\share"
    #
    # These values can be retrived using:
    #
    #  user.local_drive   # --> "Z:"
    #  user.local_path    # --> "\\server\share"
    #
    # The user.local_path value is also used by itself if only the "Local path"
    # was set for the Home folder section of the Profile tab in Active Directory
    # Users and Computers using the User#local_path= method, but here it is
    # also used in this case as well.
    def connect_drive_to(drive, path)
      @local_drive = drive
      @local_path = path
      @modified = true
    end
    
    # The User or UNIXUser Windows password. This is only set to a value other
    # than nil if the password should be changed on the next AD#sync call. Once
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
    # Active Directory using AD#sync, the password attribute is set to nil
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
    #
    # When a User or UNIXUser changes their primary Windows group, they are
    # automatically given normal group membershipt in the old primary Windows
    # group by Active Directory. This method does the same.
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
      old_group = @primary_group
      @primary_group = group
      add_group old_group
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
          @removed_groups.delete group
          group.add_user self unless group.users.include? self
        else
          raise "User is already a member of their primary group."
        end
      else
        raise "Group must be in the same directory."
      end
    end
    
    # Remove the User membership in the Group or UNIXGroup. This automatically
    # removes the User from the Group or UNIXGroup object's list of users.
    def remove_group(group)
      # This method can be called on a primary_group change. If the user was a
      # member of the primary_group, we want to make sure we remove that
      # membership. It is also possible the user was not already a member of
      # that primary_group. We only want to add that group to the
      # @removed_groups array if they were really a member, otherwise we would
      # not care.
      if @groups.include? group
        @removed_groups.push group unless @removed_groups.include? group
      end
      
      @groups.delete group
      group.remove_user self if group.users.include? self
    end
    
    # Determine if a User or UNIXUser is a member of the Group or UNIXGroup.
    # This also evaluates to true if the Group or UNIXGroup is the
    # User or UNIXUser object's primary_group.
    def member_of?(group)
      @groups.include? group || @primary_group == group
    end
    
    # Set the loaded flag. This also clears the modified flag. This should only
    # be called from AD#load and AD#sync unless you really know what you are
    # doing.
    def set_loaded
      # This allows the modified attribute to be hidden.
      @loaded = true
      @modified = false
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
    
    # Create a new UNIXUser object that represents a UNIX user in Active
    # Directory. This method takes a Hash containing arguments, some of which
    # are required and others optional. The supported arguments follow:
    #
    # * :username => The UNIXUser object's username [required]
    # * :container => The UNIXUser object's associated Container [required]
    # * :primary_group => The UNIXUser object's primary Windows group [required]
    # * :disabled => UNIXUser object disabled flag [default false]
    # * :rid => The RID of the UNIXUser object [optional]
    # * :uid => The UNIXUser UID attribute [required]
    # * :unix_main_group => The UNIXUser object's UNIX main group [required]
    # * :shell => The UNIXUser shell attribute [required]
    # * :home_directory => The UNIXUser home directory attribute [required]
    # * :nis_domain => The UNIXUser NIS domain attribute [default "radum"]
    #
    # The :username argument (case-insensitive) and the :rid argument must be
    # unique in the AD object, otherwise a RuntimeError is raised. The
    # :primary_group argument must be of the RADUM type GROUP_GLOBAL_SECURITY
    # or GROUP_UNIVERSAL_SECURITY, otherwise a RuntimeError is raised. The
    # :disabled argument indicates if the UNIXUser object should be disabled,
    # and it defaults to false. The :rid argument should not be set directly
    # except from the AD#load method itself. The :unix_main_group argument
    # must be a UNIXGroup object or a RuntimeError is raised. The UNIXUser
    # object automatically adds itself to the Container object specified by
    # the :container argument. The argument types required follow:
    #
    # * :username [String]
    # * :container [Container]
    # * :primary_group [Group or UNIXGroup]
    # * :disabled [boolean]
    # * :rid [integer]
    # * :uid [integer]
    # * :unix_main_group [UNIXGroup]
    # * :shell [String]
    # * :home_directory [String]
    # * :nis_domain [String]
    #
    # Note that a User will not be forced to change their Windows password on
    # their first login unless this is changed by calling the
    # toggle_must_change_password method. If no password is set for the User,
    # a random password will be generated. The random password will probably
    # meet Group Policy password security requirements, but it is suggested
    # that a password be set to ensure this is the case, otherwise setting the
    # User password during Active Directory creation might fail, which results
    # in a disabled Active Directory user account that has no password.
    #
    # See the documentation for each attribute method for what the default
    # values of each attribute is based on calling this method.
    def initialize(args = {})
      super args
      @uid = args[:uid] or raise "UNIXUser :uid attribute required."
      
      # The UID must be unique.
      if @container.directory.uids.include? @uid
        raise "UID #{uid} is already in use in the directory."
      end
      
      @unix_main_group = args[:unix_main_group] or raise "UNIXUser" +
                                                         " :unix_main_group" +
                                                         " argument required."
      
      if @container.directory == @unix_main_group.container.directory
        unless @unix_main_group.instance_of? UNIXGroup
          raise "UNIXUser unix_main_group must be a UNIXGroup."
        else
          @gid = @unix_main_group.gid
          @container.add_group @unix_main_group
          # The UNIXUser is already a member of their primary Windows group
          # implicitly.
          add_group @unix_main_group unless @unix_main_group == @primary_group
        end
      else
        raise "UNIXUser unix_main_group must be in the same directory."
      end
      
      @shell = args[:shell] or raise "UNIXUser :shell argument required."
      @home_directory = args[:home_directory] or raise "UNIXUser" +
                                                       " :home_directory" +
                                                       " argument required."
      @nis_domain = args[:nis_domain] || "radum"
      @gecos = @username
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
    # is loaded by AD#load from the AD object the Container belongs to.
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
    # loaded by AD#load from the AD object the Container belongs to.
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
    # AD#load from the AD object the Container belongs to.
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
    # is loaded by AD#load from the AD object the Container belongs to. This
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
    # is loaded by AD#load from the AD object the Container belongs to. This
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
    # is loaded by AD#load from the AD object the Container belongs to. This
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
    # is loaded by AD#load from the AD object the Container belongs to. This
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
    # is loaded by AD#load from the AD object the Container belongs to. This
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
    # is loaded by AD#load from the AD object the Container belongs to. This
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
    # is loaded by AD#load from the AD object the Container belongs to. This
    # only needs to be set if the shadow file information is really needed.
    # It would not be needed most of the time. This corresponds to the LDAP
    # shadowWarning attribute.
    def shadow_warning=(shadow_warning)
      @shadow_warning = shadow_warning
      @modified = true
    end
    
    # Remove the UNIXUser membership in the Group or UNIXGroup. This
    # automatically removes the UNIXUser from the Group or UNIXGroup object's
    # list of users. This method returns a RuntimeError if the group is a
    # UNIXGroup and the UNIXUser object's UNIX main group. UNIXGroup membership
    # cannot be removed for the UNIXUser object's UNIX main group because RADUM
    # enforces Windows group membership in the UNIX main group.
    def remove_group(group)
      if !self.removed && group.instance_of?(UNIXGroup) &&
         group == @unix_main_group
        raise "A UNIXUser cannot be removed from their unix_main_group."
      end
      
      super group
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
          # The UNIXUser is already a member of their primary Windows group
          # implicitly.
          add_group group unless group == @primary_group
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
