module RADUM
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
    # LDAP groupType attribute. This defaults to GROUP_GLOBAL_SECURITY when
    # a Group or UNIXGroup is created using Group.new or UNIXGroup.new, but
    # it is set to the correct value when a Group or UNIXGroup is loaded by
    # AD#load from the AD object the Container belongs to.
    attr_reader :type
    # The RID of the Group or UNIXGroup object. This correponds to part of the
    # LDAP objectSid attribute. This is set when the Group or UNIXGroup is
    # loaded by AD#load from the AD object the Container belongs to. This
    # attribute should not be specified in the Group.new or UNIXGroup.new
    # methods when creating a new Group or UNIXGroup by hand.
    attr_reader :rid
    # The LDAP distinguishedName attribute for this Group or UNIXGroup.
    attr_reader :distinguished_name
    # The User or UNIXUser objects that are members of the Group or UNIXGroup.
    # Users or UNIXUsers are not members of the Group or UNIXGroup if the Group
    # or UNIXGroup is their primary Windows group in Active Directory.
    attr_reader :users
    # An array of User or UNIXUser objects removed from the Group or UNIXGroup.
    attr_reader :removed_users
    # The Group or UNIXGroup objects that are members of the Group or UNIXGroup.
    attr_reader :groups
    # An array of Group or UNIXGroup objects removed from the Group or
    # UNIXGroup.
    attr_reader :removed_groups
    # True if the Group or UNIXGroup has been removed from the Container, false
    # otherwise. This is set by the Container if the Group is removed.
    attr_accessor :removed
    
    # Create a new Group object that represents a Windows group in Active
    # Directory. This method takes a Hash containing arguments, some of which
    # are required and others optional. The supported arguments follow:
    #
    # * :name => The Group object's name [required]
    # * :container => The Group object's associated Container [required]
    # * :type => The RADUM group type [default GROUP_GLOBAL_SECURITY]
    # * :rid => The RID of the Group object [optional]
    #
    # The :name argument (case-insensitive) and the :rid argument must be
    # unique in the AD object, otherwise a RuntimeError is raised. The :type
    # argument must be one of the RADUM group type constants. The :rid argument
    # should not be set directly except from the AD#load method itself.
    # The Group object automatically adds itself to the Container object
    # specified by the :container argument. The argument types required follow:
    #
    # * :name [String]
    # * :container [Container]
    # * :type [RADUM group type constant]
    # * :rid [integer]
    def initialize(args = {})
      @rid = args[:rid] || nil
      @container = args[:container] or raise "Group :container argument" +
                                             " required."
      
      # The RID must be unique.
      if @container.directory.rids.include? @rid
        raise "RID #{rid} is already in use in the directory."
      end
      
      @name = args[:name] or raise "Group :name argument required."
      
      # The group name (like a user) must be unique (case-insensitive). This
      # is needed in case someone tries to make the same group name in two
      # different containers.
      if @container.directory.find_group_by_name @name
        raise "Group is already in the directory."
      end
      
      @type = args[:type] || GROUP_GLOBAL_SECURITY
      @distinguished_name = "cn=" + name + "," + @container.name + "," +
                            @container.directory.root
      @users = []
      @removed_users = []
      @groups = []
      @removed_groups = []
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
          @removed_users.delete user
          user.add_group self unless user.groups.include? self
          @modified = true
        else
          raise "Group is already the User's primary_group."
        end
      else
        raise "User must be in the same directory."
      end
    end
    
    # Remove the User or UNIXUser membership in the Group. This automatically
    # removes the Group from the User or UNIXUser object's list of groups.
    def remove_user(user)
      @users.delete user
      @removed_users.push user unless @removed_users.include? user
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
      @removed_groups.delete group
      @modified = true
    end
    
    # Remove the Group or UNIXGroup membership in the Group or UNIXGroup.
    def remove_group(group)
      @groups.delete group
      @removed_groups.push group unless @removed_groups.include? group
      @modified = true
    end
    
    # Set the loaded flag. This also clears the modified flag. This should only
    # be called from AD#load and AD#sync unless you really know what you are
    # doing.
    def set_loaded
      # This allows the modified attribute to be hidden.
      @loaded = true
      @modified = false
    end
    
    # Check if the Group or UNIXGroup was loaded from Active Directory.
    def loaded?
      @loaded
    end
    
    # True if the Group or UNIXGroup has been modified. This is true for
    # manually created Group or UNIXGroup objects and false for initially
    # loaded Group and UNIXGroup objects.
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
    
    # Create a new UNIXGroup object that represents a UNIX group in Active
    # Directory. A UNIX group is a Windows group that also has UNIX attributes.
    # This method takes a Hash containing arguments, some of which are required
    # and others optional. The supported arguments follow:
    #
    # * :name => The UNIXGroup object's name [required]
    # * :container => The UNIXGroup object's associated Container [required]
    # * :type => The RADUM group type [default GROUP_GLOBAL_SECURITY]
    # * :rid => The RID of the UNIXGroup object [optional]
    # * :gid => The UNIXGroup GID attribute [required]
    # * :nis_domain => The UNIXGroup NIS domain attribute [default "radum"]
    #
    # The :name argument (case-insensitive) and the :rid argument must be
    # unique in the AD object, otherwise a RuntimeError is raised. The :type
    # argument must be one of the RADUM group type constants. The :rid argument
    # should not be set directly except from the AD#load method itself.
    # The UNIXGroup object automatically adds itself to the Container object
    # specified by the :container argument. The :gid argument specifies the
    # UNIX GID value of the UNIXGroup. The :nis_domain defaults to "radum".
    # The use of an NIS domain is not strictly required as one could simply
    # set the right attributes in Active Directory and use LDAP on clients to
    # access that data, but specifying an NIS domain allows for easy editing
    # of UNIX attributes using the GUI tools in Windows, thus the use of a
    # default value. The argument types required follow:
    #
    # * :name [String]
    # * :container [Container]
    # * :type [RADUM group type constant]
    # * :rid [integer]
    # * :gid [integer]
    # * :nis_domain [String]
    def initialize(args = {})
      super args
      @gid = args[:gid] or raise "UNIXGroup :gid argument required."
      
      # The GID must be unique.
      if @container.directory.gids.include? @gid
        raise "GID #{gid} is already in use in the directory."
      end
      
      @nis_domain = args[:nis_domain] || "radum"
      @unix_password = "*"
      # The removed flag must be set to true first since we are not in the
      # container yet.
      @removed = true
      @container.add_group self
      @removed = false
    end
    
    # Remove the User or UNIXUser membership in the UNIXGroup. This
    # automatically removes the UNIXGroup from the User or UNIXUser object's
    # list of groups. This method returns a RuntimeError if the user
    # has this UNIXGroup as their UNIX main group. UNIXGroup membership cannot
    # be removed for the UNIXUser object's UNIX main group because RADUM
    # enforces Windows group membership in the UNIX main group.
    def remove_user(user)
      if !user.removed && user.instance_of?(UNIXUser) &&
         self == user.unix_main_group
        raise "A UNIXUser cannot be removed from their unix_main_group."
      end
      
      super user
    end
    
    # The UNIXGroup UNIX NIS domain.
    def nis_domain
      @nis_domain
    end
    
    # Set the UNIXGroup UNIX NIS domain. This corresponds to the LDAP
    # msSFU30NisDomain attribute. This needs to be set even if NIS services
    # are not being used. This defaults to "radum" when a UNIXGroup is created
    # using UNIXGroup.new, but it is set to the correct value when the UNIXGroup
    # is loaded by AD#load from the AD object the Container belongs to.
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
    # to the correct value when the UNIXGroup is loaded by AD#load from the AD
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
end
