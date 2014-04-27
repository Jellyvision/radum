module RADUM
  # The Container class represents a directory entry which contains users and
  # groups, usually an orgainizational unit (OU).
  class Container
    # The String represenation of the Container object's name. The name should
    # be the LDAP distinguishedName attribute without the AD root path
    # component.
    attr_reader :name
    # The AD object the Container belongs to.
    attr_reader :directory
    # The LDAP distinguishedName attribute for this Container.
    attr_reader :distinguished_name
    # An Array of User and UNIXUser objects that are in this Container.
    attr_reader :users
    # An Array of User and UNIXUser objects set for removal from this Container.
    attr_reader :removed_users
    # An Array of Group and UNIXGroup objects that are in this Container.
    attr_reader :groups
    # An Array of Group and UNIXGroup objects set for removal from this
    # Container.
    attr_reader :removed_groups

    # Create a new Container object that represents an Active Directory
    # container or organizational unit that contains users and groups. This
    # method takes a Hash containing arguments, all of which are required.
    # The supported arguments follow:
    #
    # * :name => The relative path in Active Directory [required]
    # * :directory => The Container object's associated AD [required]
    #
    # An example instantiation follows:
    #
    #   ad = RADUM::AD.new :root => 'dc=example,dc=com',
    #                      :user => 'cn=Administrator,cn=Users',
    #                      :password => 'password',
    #                      :server => '192.168.1.1'
    #   cn = RADUM::Container.new :name => 'ou=People', :directory => ad
    #
    # The :name argument specifies the path to the container or organizational
    # unit in Active Directory equivalent to the LDAP distinguishedName
    # attribute for container or organizational unit without the root portion.
    # The :directory argument is the AD object that owns the Container. A
    # RuntimeError is raised if either of these arguments are missing.
    #
    # === Parameter Types
    #
    # * :name [String]
    # * :directory [AD]
    #
    # Extraneous spaces are removed from the :name argument. The Container :name
    # can have spaces, but extra spaces after any "," characters are removed
    # automatically along with leading and traling white space. The Container
    # must not already be in the AD or a RuntimeError is raised. Note that you
    # can create Container objects for an actual container in Active Directory
    # or an organizational unit (referred to here as a "container" since it
    # logically contains objects and this is a higher level representation).
    # Only specify Containers that are really containers ("cn=Foo") or
    # organizational units ("ou=Foo"). Also note that orgainizational units can
    # hold containers, but containers cannot hold organizational units.
    # Therefore "ou=foo,cn=bar" is invalid, but "cn=foo,ou=bar" is valid. A
    # RuntimeError is raised if this rule is violated. Lastly, Container
    # objects are in a conceptually flat namespace. In other words,
    # "cn=foo,ou=bar" is its own Container object. It is not represented as a
    # child of the "ou=bar" organizational unit. This has been accounted for
    # when synchronizing with AD#sync so that things work. For example, the
    # "cn=foo,ou=bar" Container object will cause the "ou=bar" organizational
    # unit to be created first, if necessary, before the "cn=bar" child
    # container is created.
    def initialize(args = {})
      @name = args[:name] or raise "Container :name argument required."
      @name.gsub!(/,\s+/, ",")
      @name.strip!

      if @name =~ /[Oo][Uu]=.*[Cc][Nn]=/
        raise "Container CN objects cannot contain OU objects."
      end

      @directory = args[:directory] or raise "Container :directory argument" +
                                             " required."

      # The container name (like a user) must be unique (case-insensitive).
      # We would not want someone accidently making two equal containers
      # and adding users/groups in the wrong way.
      if @directory.find_container(name)
        raise "Container is already in the directory."
      end

      @alterate_root = args[:alternate_root] || @directory.root

      @distinguished_name = @name + "," + @alternate_root
      # This has to be set first before adding the Container to the AD.
      @removed = false
      @directory.add_container self
      @users = []
      @removed_users = []
      @groups = []
      @removed_groups = []
    end

    # Add User and UNIXUser objects to the Container. User and UNIXUser objects
    # that were removed or destroyed cannot be added back again and are ignored.
    # The User or UNIXUser must have the Container as its container attribute
    # or a RuntimeError is raised.
    #
    # === Parameter Types
    #
    # * user [User or UNIXUser]
    def add_user(user)
      unless user.removed?
        if self == user.container
          # We don't want to add a user more than once.
          unless @users.include?(user)
            @users.push user
            @removed_users.delete user
            @directory.rids.push user.rid if user.rid
            @directory.uids.push user.uid if user.instance_of?(UNIXUser)
          end
        else
          raise "User must be in this container."
        end
      end
    end

    # Remove a User or UNIXUser object from the Container. This sets the
    # User or UNIXUser object's removed attribute to true. If the User or
    # UNIXUser is removed from the Container, it is effectively deleted
    # from Active Directory. Any Group or UNIXGroup objects the User or UNIXUser
    # belongs to will have their membership removed. This means that the
    # User or UNIXUser will have their Group or UNIXGroup memberships
    # removed for each Group or UNIXGroup they were in as well. The User or
    # UNIXUser cannot be added back after removed, but it will only be
    # removed from Active Directory after AD#sync is called. Any references
    # to the User or UNIXUser should be discarded. The User or UNIXUser must
    # be in the Container or a RuntimeError is raised. Already removed User
    # or UNIXUser objects are ignored.
    #
    # === Parameter Types
    #
    # * user [User or UNIXUser]
    def remove_user(user)
      return if user.removed?
      if self == user.container
        @users.delete user
        @directory.rids.delete user.rid if user.rid
        @directory.uids.delete user.uid if user.instance_of?(UNIXUser)

        @directory.groups.each do |group|
          if group.users.include?(user)
            if user.instance_of?(UNIXUser)
              group.remove_user user unless group == user.unix_main_group
            else
              group.remove_user user
            end
          end
        end

        user.set_removed

        # We have to remove the user first before we can remove the user's
        # membership in their unix_main_group. It is safe to attempt removing
        # a user from their unix_main_group if they are already removed.
        if user.instance_of?(UNIXUser)
          user.unix_main_group.remove_user user
        end

        @removed_users.push user unless @removed_users.include?(user)
      else
        raise "User must be in this container."
      end
    end

    # Destroy a reference to the User or UNIXUser. This removes any reference
    # to the User or UNIXUser from the RADUM system. This is different from
    # removing a User or UNIXUser. Removal causes the User or UNIXUser to be
    # deleted from Active Directory. Destroying the User or UNIXUser does not
    # cause the User or UNIXUser to be removed from Active Directory, but
    # it does remove all references to the User or UNIXUser from the system.
    # The User or UNIXUser must be in the Container or a RuntimeError is
    # raised. This does set the User or UNIXUser object's removed attribute
    # to true and any references to the User or UNIXUser should be discarded.
    # Once a User or UNIXUser is destroyed it cannot be added back to the
    # Container.
    #
    # === Parameter Types
    #
    # * user [User or UNIXUser]
    def destroy_user(user)
      # Note you have to allow destruction of users even if they have been
      # removed because this is the only way removed users are really deleted
      # from the RADUM environment once they are deleted from Active Directory.
      if self == user.container
        @users.delete user
        @removed_users.delete user
        @directory.rids.delete user.rid if user.rid
        @directory.uids.delete user.uid if user.instance_of?(UNIXUser)

        @directory.groups.each do |group|
          group.destroy_user user if group.users.include?(user)
        end

        user.set_removed
      else
        raise "User must be in this container."
      end
    end

    # Add Group and UNIXGroup objects to the Container. Group and UNIXGroup
    # objects that were removed or destroyed cannot be added back again and are
    # ignored. The Group or UNIXGroup must have the Container as its container
    # attribute or a RuntimeError is raised.
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def add_group(group)
      unless group.removed?
        if self == group.container
          # We don't want to add a group more than once.
          unless @groups.include?(group)
            @groups.push group
            @removed_groups.delete group
            @directory.rids.push group.rid if group.rid
            @directory.gids.push group.gid if group.instance_of?(UNIXGroup)
          end
        else
          raise "Group must be in this container."
        end
      end
    end

    # Remove a Group or UNIXGroup object from the Container. This sets the
    # Group or UNIXGroup object's removed attribute to true. A Group or
    # UNIXGroup cannot be removed if it is still any User object's primary
    # Windows group. A UNIXGroup cannot be removed if it is any User object's
    # UNIX main group. In both cases, a RuntimeError will be raised. If the
    # Group or UNIXGroup is removed from the Container, it is effectively
    # deleted from Active Directory. Any Group or UNIXGroup objects the Group or
    # UNIXGroup belongs to will have their membership removed. This
    # means that the Group or UNIXGroup will have their Group or UNIXGroup
    # memberships removed for each Group or UNIXGroup they were in as well.
    # The Group or UNIXGroup cannot be added back after removed, but it will
    # only be removed from Active Directory after AD#sync is called. Any
    # references to the Group or UNIXGroup should be discarded. The Group or
    # UNIXGroup must be in the Container or a RuntimeError is raised. Already
    # removed Group or UNIXGroup objects are ignored.
    #
    # There are further checks in Active Directory to make sure the Group
    # or UNIXGroup can really be removed. A warning is displayed if the Group
    # or UNIXGroup cannot be removed in the AD#sync call. In this method,
    # RADUM only checks objects it knows about at the time of the call.
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def remove_group(group)
      return if group.removed?
      if self == group.container
        # We cannot remove a group that still has a user referencing it as
        # their primary_group or unix_main_group.
        @directory.users.each do |user|
          if group == user.primary_group
            raise "Cannot remove group #{group.name}: it is " +
                  "#{user.username}'s primary Windows group."
          end

          if user.instance_of?(UNIXUser)
            if group == user.unix_main_group
              raise "Cannot remove group #{group.name}: it is " +
                    "#{user.username}'s UNIX main group."
            end
          end
        end

        @groups.delete group
        @directory.rids.delete group.rid if group.rid
        @directory.gids.delete group.gid if group.instance_of?(UNIXGroup)

        @directory.groups.each do |current_group|
          if current_group.groups.include?(group)
            current_group.remove_group group
          end
        end

        @directory.users.each do |user|
          if user.groups.include?(group)
            user.remove_group group
          end
        end

        group.set_removed
        @removed_groups.push group unless @removed_groups.include?(group)
      else
        raise "Group must be in this container."
      end
    end

    # Destroy a reference to the Group or UNIXGroup. This removes any reference
    # to the Group or UNIXGroup from the RADUM system. This is different from
    # removing a Group or UNIXGroup. Removal causes the Group or UNIXGroup to be
    # deleted from Active Directory. Destroying the Group or UNIXGroup does not
    # cause the Group or UNIXGroup to be removed from Active Directory, but
    # it does remove all references to the Group or UNIXGroup from the system.
    # The Group or UNIXGroup must be in the Container or a RuntimeError is
    # raised. This does set the Group or UNIXGroup object's removed attribute
    # to true and any references to the Group or UNIXGroup should be discarded.
    # Once a Group or UNIXGroup is destroyed it cannot be added back to the
    # Container.
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def destroy_group(group)
      # Note you have to allow destruction of groups even if they have been
      # removed because this is the only way removed groups are really deleted
      # from the RADUM environment once they are deleted from Active Directory.
      if self == group.container
        # We cannot destroy a group that still has a user referencing it as
        # their primary_group or unix_main_group.
        @directory.users.each do |user|
          if group == user.primary_group
            raise "Cannot destroy group #{group.name}: it is " +
                  "#{user.username}'s primary Windows group."
          end

          if user.instance_of?(UNIXUser)
            if group == user.unix_main_group
              raise "Cannot destroy group #{group.name}: it is " +
                    "#{user.username}'s UNIX main group."
            end
          end
        end

        @groups.delete group
        @removed_groups.delete group
        @directory.rids.delete group.rid if group.rid
        @directory.gids.delete group.gid if group.instance_of?(UNIXGroup)

        @directory.groups.each do |current_group|
          if current_group.groups.include?(group)
            current_group.destroy_group group
          end
        end

        @directory.users.each do |user|
          user.destroy_group group
        end

        group.set_removed
      else
        raise "Group must be in this container."
      end
    end

    # True if the Container has been removed from its AD, false otherwise.
    def removed?
      @removed
    end

    # Set the Container removed flag.
    def set_removed # :nodoc:
      @removed = true
    end

    # The String representation of the Container object.
    def to_s
      "Container <#{@name}> [#{@distinguished_name}]"
    end
  end
end
