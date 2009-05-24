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
end
