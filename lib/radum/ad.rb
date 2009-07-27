# The RADUM module provides an interface to Microsoft Active Directory for
# working with users and groups. The User class represents a standard Windows
# user account. The UNIXUser class represents a Windows account that has UNIX
# attributes. Similarly, the Group class represents a standard Windows group,
# and a UNIXGroup represents a Windows group that has UNIX attributes. UNIX
# attributes are supported if Active Directory has been extended, such as
# when Microsoft Identity Management for UNIX has been installed. LDAP
# extensions for UNIX are not required if only Windows users and groups are
# operated on. This module concentrates only on users and groups at this time.
#
# This is a pure Ruby implementation. Windows command line tools are not
# used in any way, so this will work from other platforms such as Mac OS X
# and Linux in addition to Windows. RADUM does require the Active Directory
# server to support SSL because that is a requirement for creating user
# accounts through LDAP. This means that a domain must have a certificate
# server. Using a self-signed certificate should be fine.
#
# RADUM considers its view of user and group attributes to be authoritative,
# with the exception that it will not modify the members of a group that it
# is not already aware of. The general RADUM pattern is:
#
# * AD.new(...)
# * Container.new(...) [for any Containers of interest]
# * AD#load()
# * Create, update, or remove existing loaded objects.
# * AD#sync()
#
# See the class documenation for more details, especially the AD#load and
# AD#sync methods.
#
# = AD
#
# The AD class represents an Active Directory. An AD object can be created
# with something like the following code:
#
#  ad = RADUM::AD.new :root => 'dc=example,dc=com',
#                     :user => 'cn=Administrator,cn=Users',
#                     :password => 'password',
#                     :server => '192.168.1.1'
#
# The AD class will connect to Active Directory when it needs to do so
# automatically. A connection will not be made until required. Some arguments
# in RADUM are specified using a relative path sans the :root argument to
# the AD.new method, such as the :user argument and Container names discussed
# next. The AD class provides a read-only ldap attriubte that allows direct
# interaction with Active Directory if needed. The AD object automatically
# adds the "cn=Users" Container object because most users have "Domain Users"
# as their primary Windows group. The primary Windows group is necessary for
# creating User and UNIXUser objects, especially when AD#load is called. Note
# that the :root and :user arguments can use lowercase or uppercase for the
# "dc=", "cn=", or "ou=" path elements.
#
# = Container
#
# Container objects are added to the AD object before AD#load is called in
# most cases. Container objects can be created with something like the
# following code:
#
#  people = RADUM::Container.new :name => 'ou=People',
#                                :directory => ad
#
# It is possible to have nested Container objects as well, such as:
#
#  staff = RADUM::Container.new :name => 'ou=Staff,ou=People',
#                               :directory => ad
#  faculty = RADUM::Container.new :name => 'ou=Faculty,ou=People',
#                                 :directory => ad
#  grads = RADUM::Container.new :name => 'ou=Grads,ou=People',
#                               :directory => ad
#
# Container objects do not have a direct reference to Container objects they
# logically contain, but the RADUM code handles these cases when creating and
# removing Container objects from Active Directory. Container objects do have
# references to all users and groups they contain as well as the AD object
# they belong to.
#
# The :name of a Container object is the only other case where a relative path
# is used. The :name should be the directory path (the distinguished name) sans
# the :root path given to the AD object that owns the Container. Container
# objects can be Active Directory organizational units or containers. Note that
# Active Directory containers cannot contain organizational units, but the
# reverse is true, therefore the following :name would be invalid:
#
#  invalid = RADUM::Container.new :name => 'ou=Staff,cn=People',
#                                 :directory => ad
#
# but the following :name is valid:
#
#  valid = RADUM::Container.new :name => 'cn=Staff,ou=People',
#                               :directory => ad
#
# In general, one should use Active Directory organizational units instead of
# containers. They are much more useful. The :name argument can use lowercase
# or uppercase for the "cn=" and "ou=" path elements.
#
# Container objects should be added to the AD object before doing serious
# work in the general case for the best results. This doesn't necessarily have
# to be done if only creating new objects, but it is still a good idea that
# won't hurt anyway. The "cn=Users" container is added by default to an AD
# object when it is created to help make things easier as it is usually
# required, and if it really is not needed, it should not take too many
# resources.
#
# == Removing Container Objects
#
# Removing a Container causes that Container to be removed from Active Directory
# when AD#sync is called, but only if that is possible. Container objects
# cannot be removed if they have groups that cannot be removed nor if they
# logically contain other Container objects. When calling the
# AD#remove_container method, checks are made for all the objects RADUM knows
# about. When calling AD#sync checks are made in Active Directory. See the
# AD#remove_container method documentation for more details. Note that removing
# a Container will always remove all User or UNIXUser objects it contains
# regardless, and when AD#sync is called, all possible objects that can be
# removed will be due to the implementation of AD#remove_container.
#
# It is also possible to destroy a Container. Unlike with users and groups,
# destroying a Container with AD#destroy_container simply removes the reference
# to the Container in the AD object. It does not result in the Container
# objects contents from being removed. The Container simply will not be
# processed in AD#load and AD#sync calls. The AD object determines all user
# and group references based on the Container objects it owns.
#
# = Loading the AD Object
#
# Once the Container objects have been added to the AD object, the AD object
# can be loaded. Calling AD#load is straightforward:
#
#  ad.load
#
# This will create User, UNIXUser, Group, and UNIXGroup objects to represent
# all such objects in the Container objects added to the AD object. The AD#load
# method determines if a user or group is a Windows or UNIX type based on the
# object's LDAP attributes. AD#load can be called multiple times, but it will
# ignore loading any user or group objects that already exist in the RADUM
# environment.
#
# = Working with Users and Groups
#
# User and group object creation results in the users and groups being added to
# their Container object automatically. Users and groups also have direct
# references to their corresponding collections of groups for users and
# groups plus users for groups (since groups can contain other groups as
# members). User memberships in groups can be handled from either perspective
# due to this automatic handling:
#
# * Users can be added to groups through User#add_group.
# * Users can be added to groups through Group#add_user.
#
# Group membership in groups has to be handled by using the Group#add_group
# method only, which adds the Group or UNIXGroup used as the argument as a
# member of the Group object to which the method belongs.
#
# RADUM ensures that duplicate users and groups cannot be created, including
# specific attributes of those objects which must be unique. Trying to do
# something that would result in duplication generally raises a RuntimeError.
#
# == Creating Group and UNIXGroup Objects
#
# Group objects represent Windows groups and UNIXGroup objects represent UNIX
# groups, which are Windows groups that have UNIX attributes. Examples include:
#
#  research_users = RADUM::Group.new :name => 'Research Users',
#                                    :container => faculty
#  unix_staff = RADUM::UNIXGroup.new :name => 'staff',
#                                    :container => staff,
#                                    :gid => 1005
#
# There are additional argumements in both cases. See Group.new and
# UNIXGroup.new for additional details. In both cases, the :rid argument should
# only be used by AD#load to specify the group object's relative identifier,
# which is based on the LDAP objectSid attribute. There is an :nis_domain
# argument for UNIXGroup objects that defaults to "radum" if not specified.
# NIS is not required for using Active Directory in a centralized authentication
# design. One could access the UNIX attributes through LDAP directly for
# example. However, the NIS domain needs to be present if one wants to use
# the Active Directory Users and Groups GUI tool, therefore one is specified
# by default. The :type argument applies to both Group and UNIXGroup objects.
# The default value is RADUM::GROUP_GLOBAL_SECURITY, which is the default
# when creating group objects using the Active Directory Users and Groups GUI
# tool in Windows. More details about the restrictions for certain group types
# can be found in the User#primary_group= method documentation.
#
# There is a useful method for finding the next available GID for the UNIXGroup
# object's :gid argument:
#
#  gid = ad.load_next_gid
#
# The AD#load_next_gid method searches Active Directory and the current RADUM
# objects for the next GID value that can be used. The :gid attribute for a
# UNIXGroup also becomes a UNIXUser object's GID value, depending on the
# :unix_main_group for that UNIXUser.
#
# == Removing Group and UNIXGroup Objects
#
# Group and UNIXGroup objects can be removed from RADUM by using the following
# method for the Container object that they belong to:
#
#  faculty.remove_group research_users
#
# or by searching for a group:
#
#  faculty.remove_group ad.find_group_by_name('Research Users')
#
# Removing a group causes that group to be removed from Active Directory when
# AD#sync is called, but only if that is possible. Group and UNIXGroup objects
# cannot be removed if they are the primary Windows group of any user in
# Active Directory nor if they are the UNIX main group for any UNIXUser objects
# in Active Directory. When calling the Container#remove_group method, checks
# are made for all the objects RADUM knows about. When calling AD#sync checks
# are made for all users in Active Directory.
#
# It is also possible to destroy a Group or UNIXGroup object. Destroying a
# Group or UNIXGroup does not remove the object from Active Directory. Instead
# it removes all references to the object in RADUM itself. The same checks are
# made against all objects RADUM knows about before destroying the object can
# succeed. See the Container#destroy_group method documentation for more
# details.
#
# In both cases, any external references ot the orginal object should be
# discarded.
#
# == Converting Group and UNIXGroup Objects
#
# It is possible to convert Group objects to UNIXGroup objects and vice versa
# under certain conditions. Group objects can converted to UNIXGroup objects
# if the Group is not the primary Windows group for a user RADUM knows about.
# This is not really a strict requirement for users in Active Directory, but
# it is a limitation of the current RADUM implementation. UNIXGroup objects
# can be converted to Group objects with the same implementation restriction
# with the additional restriction that the UNIXGroup cannot be the UNIX main
# group for any user in Active Directory. Conversion causes this check to be
# made outside of the AD#load and AD#sync methods immediately before proceeding.
# If the conversion is successful, a new object of the desired type is created
# and placed into the RADUM system in place of the original object. Any external
# references to the orginal object should be discarded as they will be
# treated as if they were removed objects, even though they are not removed
# from Active Directory. Note that UNIX attributes are removed from UNIXGroup
# objects in Active Directory immediately before AD#sync when converted to
# Group objects.
#
# == Creating User and UNIXUser Objects
#
# User objects represent Windows users and UNIXUser objects represent UNIX
# users, which are Windows users that have UNIX attributes. Examples include:
#
#  RADUM::User.new :username => 'martin',
#                  :container => faculty,
#                  :primary_group => ad.find_group_by_name('Domain Users')
#  RADUM::UNIXUser.new :username => 'rowland',
#                      :container => staff,
#                      :primary_group => ad.find_group_by_name('Domain Users'),
#                      :uid => 5437,
#                      :unix_main_group => unix_staff,
#                      :shell => '/bin/bash',
#                      :home_directory => '/home/rowland'
#
# There are additional argumements in both cases. See User.new and
# UNIXUser.new for additional details. In both cases, the :rid argument should
# only be used by AD#load to specify the user object's relative identifier,
# which is based on the LDAP objectSid attribute. There is an :nis_domain
# argument for UNIXUser objects that defaults to "radum" if not specified.
# NIS is not required for using Active Directory in a centralized authentication
# design. One could access the UNIX attributes through LDAP directly for
# example. However, the NIS domain needs to be present if one wants to use
# the Active Directory Users and Groups GUI tool, therefore one is specified
# by default. The :disabled argument applies to both User and UNIXUser objects.
# The default value is false. The password attribute for User and UNIXUser
# objects is nil unless set, and when set it causes the user in Active Directory
# to have that password if it meets the Group Policy password requirements.
# Once set through AD#sync, the password attribute is set to nil again. The
# GID value for a UNIXUser comes from its :unix_main_group argument UNIXGroup
# value. There are many attributes that can be set for User and UNIXUser
# objects. See the User and UNIXUser class documentation for more details.
#
# There is a useful method for finding the next available UID for the UNIXUser
# object's :uid argument:
#
#  uid = ad.load_next_uid
#
# The AD#load_next_uid method searches Active Directory and the current RADUM
# objects for the next UID value that can be used.
#
# == Removing User and UNIXUser Objects
#
# User and UNIXUser objects can be removed from RADUM by using the following
# method for the Container object that they belong to:
#
#  faculty.remove_user ad.find_user_by_username('martin')
#
# or by specifying a reference to a User or UNIXUser object directly.
#
# Removing a user causes that user to be removed from Active Directory when
# AD#sync is called.
#
# It is also possible to destroy a User or UNIXUser object. Destroying a
# User or UNIXUser does not remove the object from Active Directory. Instead
# it removes all references to the object in RADUM itself.
#
# In both cases, any external references ot the orginal object should be
# discarded.
#
# == Converting User and UNIXUser Objects
#
# It is possible to convert User objects to UNIXUser objects and vice versa.
# If the conversion is successful, a new object of the desired type is created
# and placed into the RADUM system in place of the original object. Any external
# references to the orginal object should be discarded as they will be
# treated as if they were removed objects, even though they are not removed
# from Active Directory. Note that UNIX attributes are removed from UNIXUser
# objects in Active Directory immediately before AD#sync when converted to
# User objects.
#
# = Synchronizing to Active Directory
#
# After making any changes, synchronizing those changes to Active Directory can
# be accomplished with the following:
#
#  ad.sync
#
# This method can be called whenever changes are made. Changes in RADUM are
# considered authoritative and Active Directory objects are updated to reflect
# their attributes as RADUM sees the world. This is true for group memberships
# except for members that RADUM does not know about. This means that AD#sync
# will not cause users and groups it does not know about to be removed from
# a Group or UNIXGroup it does know about, but it will remove users and groups
# that have been explicitly removed in the RADUM system.
#
# == Windows Server Versions
#
# RADUM has been exlusively tested against Windows Server 2008. The testing
# system had Microsoft Identity Management for UNIX installed and had the
# Certificate Services Role added. RADUM should also work against Windows
# Server 2003, but that has not been tested yet. Microsoft Identity Management
# for UNIX is generally required for UNIXUser and UNIXGroup objects if desired,
# and the Certificate Services Role is required in the domain because SSL is
# required for creating User and UNIXUser objects using LDAP.
#
# Author:: Shaun Rowland <mailto:rowand@shaunrowland.com>
# Copyright:: Copyright 2009 Shaun Rowland. All rights reserved.
# License:: BSD License included in the project LICENSE file.

module RADUM
  # Group type constants.
  #
  # These are the Fixnum representations of what should be Bignum objects in
  # some cases as far as I am aware. In the Active Directory Users and Groups
  # GUI tool, they are shown as hexidecimal values, indicating they should be
  # Bignums (well, some of them). However, if you try to edit the values in
  # that tool (with advanced attribute editing enabled or with the ADSI Edit
  # tool) these show up as the Fixnum values here. We are going to stick with
  # that, even though it is lame. I could not pull these out as Bignum objects.
  # Some of these are small enough to be Fixnums though, so I left them as their
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
  # communication between the Container, User, UNIXUser, Group, and UNIXGroup
  # objects and Active Directory are handled by the AD object. The AD object
  # should be the first object created, generally followed by Container objects.
  # The Container object requires an AD object. All other objects require a
  # Container object.
  class AD
    # A handle the the Net::LDAP object used for this AD.
    attr_reader :ldap
    # The root of the Active Directory. This is a String representing an LDAP
    # path, such as "dc=example,dc=com".
    attr_reader :root
    # The domain name of the Active Directory. This is calculated from the root
    # attribute. This is automatically made lowercase.
    attr_reader :domain
    # The Active Directory user used to connect to the Active Directory. This
    # is specified using an LDAP path to the user account, without the root
    # component, such as "cn=Administrator,cn=Users". This defaults to
    # "cn=Administrator,cn=Users" when an AD is created using AD.new.
    attr_reader :user
    # The server hostname or IP address of the Active Directory server. This
    # defaults to "localhost" when an AD is created using AD.new.
    attr_reader :server
    # The minimum UID value to use if no other UIDs are found. This defaults to
    # 1000.
    attr_accessor :min_uid
    # The array of UID values from UNIXUser objects in the AD object. This is
    # automatically managed by the other objects and should not be modified
    # directly.
    attr_accessor :uids
    # The minimum GID value to use if no other GIDs are found. This defaults to
    # 1000.
    attr_accessor :min_gid
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
    
    # Create a new AD object that represents an Active Directory environment.
    # This method takes a Hash containing arguments, some of which are required
    # and others optional. The supported arguments follow:
    #
    # * :root => The root of the Active Directory [required]
    # * :user => The user for an LDAP bind [default "cn=Administrator,cn=Users"]
    # * :password => The user password for an LDAP bind [optional]
    # * :server => The Active Directory server host [default "localhost"]
    #
    # RADUM requires TLS to create user accounts in Active Directory properly,
    # so you will need to make sure you have a certificate server so that you
    # can connect with SSL on port 636. An example instantiation follows:
    #
    #   ad = RADUM::AD.new :root => 'dc=example,dc=com',
    #                      :user => 'cn=Administrator,cn=Users',
    #                      :password => 'password',
    #                      :server => '192.168.1.1'
    #
    # The :user argument specifies the path to the user account in Active
    # Directory equivalent to the distinguished_name attribute for the user
    # without the :root portion. The :server argument can be an IP address
    # or a hostname. The :root argument is required. If it is not specified,
    # a RuntimeError is raised.
    #
    # === Parameter Types
    #
    # * :root [String]
    # * :user [String]
    # * :password [String]
    # * :server [String]
    #
    # A Container object for "cn=Users" is automatically created and added to
    # the AD object when it is created. This is meant to be a convenience
    # because most, if not all, User and UNIXUser objects will have the
    # "Domain Users" Windows group as their primary Windows group. It is
    # impossible to remove this Container.
    def initialize(args = {})
      @root = args[:root] or raise "AD :root argument required."
      @root.gsub!(/\s+/, "")
      @domain = @root.gsub(/[Dd][Cc]=/, "").gsub(/,/, ".").downcase
      @user = args[:user] || "cn=Administrator,cn=Users"
      @password = args[:password]
      @server = args[:server] || "localhost"
      @containers = []
      @removed_containers = []
      @min_uid = 1000
      @uids = []
      @min_gid = 1000
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
      @cn_users = Container.new :name => "cn=Users", :directory => self
    end
    
    # The port number used to communicate with the Active Directory server.
    def port
      @port
    end
    
    # Set the port number used to communicate with the Active Directory server.
    # This defaults to 636 for TLS in order to create user accounts properly,
    # but can be set here for nonstandard configurations.
    #
    # === Parameter Types
    #
    # * port [integer]
    def port=(port)
      @port = port
      @ldap.port = port
    end
    
    # Find a Container in the AD by name. The search is case-insensitive. The
    # Container is returned if found, otherwise nil is returned.
    #
    # === Parameter Types
    #
    # * name [String]
    def find_container(name)
      @containers.find do |container|
        # This relies on the fact that a container name must be unique in a
        # directory.
        container.name.downcase == name.downcase
      end
    end
    
    # Add a Container a container to the AD. The Container must have the AD
    # as its directory attribute or a RuntimeError is raised. Container objects
    # that were removed cannot be added back and are ignored.
    #
    # === Parameter Types
    #
    # * container [Container]
    def add_container(container) # :nodoc:
      return if container.removed?
      
      if self == container.directory
        # We don't want to add the Container more than once.
        @containers.push container unless @containers.include?(container)
        @removed_containers.delete container
      else
        raise "Container must be in the same directory."
      end
    end
    
    # Remove a Container from the AD. This attempts to set the Container
    # object's removed attribute to true as well as remove any User, UNIXUser,
    # Group, and UNIXGroup objects it contains. If any Group or UNIXGroup
    # object cannot be removed because it is a dependency, the Container cannot
    # be fully removed either, but all objects that can be removed will be
    # removed. This can happen if a Group or UNIXGroup is another User or
    # UNIXUser object's primary Windows group or UNIX main group and that User
    # or UNIXUser is not in the same Container. Removed Container objects are
    # ignored.
    #
    # Note that this method might succeed based on the user and group objects
    # it knows about, but it still might fail when AD#sync is called because a
    # more extensive Active Directory search will be performed at that point.
    # In any case, all users will be removed and all groups (and the Container)
    # if possible. This method is greedy in that it tries to remove as many
    # objects from Active Directory as possible.
    #
    # This method refuses to remove the "cn=Users" container as a safety
    # measure. There is no error raised in this case, but a warning is logged
    # using RADUM::logger with a log level of LOG_NORMAL.
    #
    # Any external reference to the Container should be discarded unless it
    # was not possible to fully remove the Container. This method returns a
    # boolean that indicates if it was possible to fully remove the Container.
    #
    # === Parameter Types
    #
    # * container [Container]
    def remove_container(container)
      return if container.removed?
      
      if container == @cn_users
        RADUM::logger.log("Cannot remove #{container.name} - safety measure.",
                          LOG_NORMAL)
        return false
      end
      
      can_remove = true
      
      # Note in the next two cases we are removing objects from the Container's
      # array of those objects, thus it is necessary to clone the array or
      # modifications will mess up the iteration.
      container.users.clone.each do |user|
        container.remove_user user
      end
      
      container.groups.clone.each do |group|
        begin
          container.remove_group group
        rescue RuntimeError => error
          RADUM::logger.log(error, LOG_NORMAL)
          can_remove = false
        end
      end
      
      @containers.each do |current_container|
        next if current_container == container
        
        if current_container.name =~ /#{container.name}/
          RADUM::logger.log("Container #{container.name} contains container " +
                            "#{current_container.name}.", LOG_NORMAL)
          can_remove = false
        end
      end
      
      if can_remove
        @containers.delete container
        
        unless @removed_containers.include?(container)
          @removed_containers.push container
        end
        
        container.set_removed
      else
        RADUM::logger.log("Cannot fully remove container #{container.name}.",
                          LOG_NORMAL)
      end
      
      can_remove
    end
    
    # Destroy all references to a Container. This can be called regardless of
    # any other status because all internal references to User, UNIXUser,
    # Group, and UNIXGroup objects are done implicitly from the AD collection
    # of Container objects. Once the Container reference is gone, its objects
    # will no longer be seen. Destroying a Container will not implicilty
    # remove its objects. They simply will no longer be processed at all.
    #
    # This method refuses to destroy the "cn=Users" container as a safety
    # measure. There is no error raised in this case, but a warning is logged
    # using RADUM::logger with a log level of LOG_NORMAL.
    #
    # Any external references to the Container should be discarded.
    #
    # === Parameter Types
    #
    # * container [Container]
    def destroy_container(container)
      # We have to allow removed Container objects to be destroyed because
      # that's the only way they are deleted from the RADUM environment
      # when they are deleted from Active Directory.
      if container == @cn_users
        RADUM::logger.log("Cannot destroy #{container.name} - safety measure.",
                          LOG_NORMAL)
        return
      end
      
      @containers.delete container
      # Removed Containers can be destroyed as well, so we want to make sure
      # all references are removed.
      @removed_containers.delete container
      container.set_removed
    end
    
    # Returns an Array of all User and UNIXUser objects in the AD.
    def users
      all_users = []
      
      @containers.each do |container|
        all_users += container.users
      end
      
      all_users
    end
    
    # Returns an Array of all removed User and UNIXUser objects in the AD.
    def removed_users
      all_removed_users = []
      
      @containers.each do |container|
        all_removed_users += container.removed_users
      end
      
      # We also need to check removed Containers too because they can have
      # removed users too.
      @removed_containers.each do |container|
        all_removed_users += container.removed_users
      end
      
      all_removed_users
    end
    
    # Find a User or UNIXUser in the AD object. The first argument is a boolean
    # that indicates if the search should be for removed users. It is optional
    # and defaults to false. The second required argument is a block.
    # The block is passed each User and UNIXUser object and contains the
    # desired testing expression. Attributes for either User or UNIXUser
    # objects can be used without worrying about the accessor methods existing.
    # Examples follow:
    #
    # * Find a User or UNIXUser by username:
    #  find_user { |user| user.username == "username" }
    # * Find a UNIXUser by gid:
    #  find_user { |user| user.gid == 1002 }
    # * Find a removed User or UNIXUser by username:
    #  find_user(true) { |user| user.username == "username" }
    # * Find a removed UNIXUser by gid:
    #  find_user(true) { |user| user.gid == 1002 }
    #
    # If no block is given the method returns nil. If the User or UNIXUser is
    # not found, the method also returns nil, otherwise the User or UNIXUser
    # object found is returned.
    #
    # There are convenient find_user_by_<attribute> methods defined that take
    # care of the example cases here as well, but this method allows any block
    # test to be given.
    #
    # === Parameter Types
    #
    # * removed [boolean]
    # * [block]
    def find_user(removed = false)
      if block_given?
        if removed
          search_users = removed_users
        else
          search_users = users
        end
        
        found = search_users.find do |user|
          begin
            yield user
          rescue NoMethodError
          end
        end
        
        return found if found
        return nil
      end
      
      return nil
    end
    
    # Find a User or UNIXUser in the AD by username. The search is
    # case-insensitive. The User or UNIXUser is returned if found, otherwise
    # nil is returned. Specify the second argument as true if you wish to
    # search for removed User or UNIXUser objects.
    #
    # === Parameter Types
    #
    # * username [String]
    # * removed [boolean]
    def find_user_by_username(username, removed = false)
      find_user removed do |user|
        user.username.downcase == username.downcase
      end
    end
    
    # Find a User or UNIXUser in the AD by RID. The User or UNIXUser is
    # returned if found, otherwise nil is returned. Specify the second argument
    # as true if you wish to search for removed User or UNIXUser objects.
    #
    # === Parameter Types
    #
    # * rid [integer]
    # * removed [boolean]
    def find_user_by_rid(rid, removed = false)
      find_user(removed) { |user| user.rid == rid }
    end
    
    # Find a UNIXUser in the AD by UID. The UNIXUser is returned if found,
    # otherwise nil is returned. Specify the second argument as true if you
    # wish to search for removed UNIXUser objects.
    #
    # === Parameter Types
    #
    # * uid [integer]
    # * removed [boolean]
    def find_user_by_uid(uid, removed = false)
      find_user(removed) { |user| user.uid == uid }
    end
    
    # Find a User or UNIXUser in the AD by distinguished name. The search is
    # case-insensitive. The User or UNIXUser is returned if found, otherwise
    # nil is returned. Specify the second argument as true if you wish to
    # search for removed User or UNIXUser objects.
    #
    # === Parameter Types
    #
    # * dn [String]
    # * removed [boolean]
    def find_user_by_dn(dn, removed = false)
      find_user removed do |user|
        user.distinguished_name.downcase == dn.downcase
      end
    end
    
    # Convert a User to a UNIXUser. This method returns the new UNIXUser
    # if successful, otherwise there will be a RuntimeError somewhere first.
    # The original User is destroyed with Container#destroy_user and a new
    # UNIXUser is created with the same information. New UNIX attributes will
    # be added to Active Directory. Any external references to the old User
    # should be discarded and replaced with the new UNIXUser object returned.
    # Supported arguments follow:
    #
    # * :user => The User to convert to a UNIXUser [required]
    # * :uid => The UNIXUser UID attribute [required]
    # * :unix_main_group => The UNIXUser object's UNIX main group [required]
    # * :shell => The UNIXUser shell attribute [required]
    # * :home_directory => The UNIXUser home directory attribute [required]
    # * :nis_domain => The UNIXUser NIS domain attribute [default "radum"]
    #
    # The :uid argument specifies the UNIX UID value of the UNIXUser. The
    # :unix_main_group argument must be a UNIXGroup object or a RuntimeError
    # is raised. The :nis_domain defaults to "radum". The use of an NIS domain
    # is not strictly required as one could simply set the right attributes in
    # Active Directory and use LDAP on clients to access that data, but
    # specifying an NIS domain allows for easy editing of UNIX attributes
    # using the GUI tools in Windows, thus the use of a default value.
    #
    # === Parameter Types
    #
    # * :user [User]
    # * :uid [integer]
    # * :unix_main_group [UNIXGroup]
    # * :shell [String]
    # * :home_directory [String]
    # * :nis_domain [String]
    #
    # If the :user argument is not a User object, a RuntimeError is raised.
    # If the User has already been removed a RuntimeError is raised.
    # The :uid argument is also checked first in case it already is in use
    # so that the original user is not destroyed by accident due to an error.
    #
    # In this case, unlike when simply creating a UNIXUser object, all UIDs
    # are checked, including those already in Active Directory.
    #
    # No changes to the User happen until AD#sync is called.
    def user_to_unix_user(args = {})
      user = args[:user]
      
      # Make sure we are working with a User object only.
      unless user.instance_of?(User)
        raise "user_to_unix_user :user argument just be a User object."
      end
      
      if user.removed?
        raise "user_to_unix_user :user has been removed."
      end
      
      uid = args[:uid]
      all_uids = load_ldap_uids
      
      # The UID must be unique.
      if (all_uids + @uids).include?(uid)
        raise "UID #{uid} is already in use in the directory."
      end
      
      unix_main_group = args[:unix_main_group]
      
      unless unix_main_group.instance_of?(UNIXGroup)
        raise "user_to_unix_user :unix_main_group is not a UNIXGroup object."
      end
      
      shell = args[:shell]
      home_directory = args[:home_directory]
      nis_domain = args[:nis_domain]
      # User attributes.
      username = user.username
      container = user.container
      primary_group = user.primary_group
      disabled = user.disabled?
      rid = user.rid
      first_name = user.first_name
      initials = user.initials
      middle_name = user.middle_name
      surname = user.surname
      script_path = user.script_path
      profile_path = user.profile_path
      local_path = user.local_path
      local_drive = user.local_drive
      password = user.password
      must_change_password = user.must_change_password?
      groups = user.groups.clone
      removed_groups = user.removed_groups.clone
      loaded = user.loaded?
      
      # Destroy the user now that we have its information.
      container.destroy_user user
      user = UNIXUser.new :username => username, :container => container,
                          :primary_group => primary_group,
                          :disabled => disabled, :rid => rid, :uid => uid,
                          :unix_main_group => unix_main_group,
                          :shell => shell, :home_directory => home_directory,
                          :nis_domain => nis_domain
      
      # Set the user to loaded if it was loaded orginally. This sets the
      # modified attribute to false, but the actions below will ensure the
      # modified attribute is actually true when we are done, which is required
      # in order to update the attributes in Active Directory through AD#sync.
      user.set_loaded if loaded
      
      # Set other User attributes.
      user.first_name = first_name
      user.initials = initials
      user.middle_name = middle_name
      user.surname = surname
      user.script_path = script_path
      user.profile_path = profile_path
      
      # Figure out the Windows home directory type attributes.
      if local_path && local_drive
        user.connect_drive_to local_drive, local_path
      elsif local_path
        user.local_path = local_path
      end
      
      user.password = password
      
      if must_change_password
        user.force_change_password
      end
      
      (groups + removed_groups).each do |group_member|
        user.add_group group_member
      end
      
      removed_groups.each do |group_member|
        user.remove_group group_member
      end
      
      user
    end
    
    # Convert a UNIXUser to a User. This method returns the new User
    # if successful, otherwise there will be a RuntimeError somewhere first.
    # The original UNIXUser is destroyed with Container#destroy_user and a
    # new User is created with the same information where applicable. Old
    # UNIX attributes will be removed from Active Directory if possible
    # immediately (not waiting on AD#sync because AD#sync will think this is
    # now only a User object with no UNIX attributes). Any external references
    # to the old UNIXUser should be discarded and replaced with the new User
    # object returned. Supported arguments follow:
    #
    # * :user => The UNIXUser to convert to a User [required]
    # * :remove_unix_groups => Remove UNIXGroup memberships [default false]
    #
    # The :user argument is the UNIXUser to convert. If the :user argument
    # is not a UNIXUser object, a RuntimeError is raised. If the UNIXUser
    # has already been removed a RuntimeError is raised. The :remove_unix_groups
    # argument is a boolean flag that determines if the new User object should
    # continue to be a member of the UNIXGroup objects it was previously.
    # UNIXUser objects are members of their UNIXGroup objects from the Windows
    # perspective by default because they are members from the UNIX perspective.
    # This is the default behavior in RADUM. The default action is to not remove
    # their Windows group memberships when converting a UNIXUser to a User.
    #
    # === Parameter Types
    #
    # * :user [UNIXUser]
    # * :remove_unix_groups [boolean]
    #
    # UNIX attributes are removed from Active Directory immedately if it is
    # actually possible to destroy the UNIXUser properly without waiting for
    # AD#sync to be called.
    def unix_user_to_user(args = {})
      user = args[:user]
      
      # Make sure we are working with a UNIXUser object only.
      unless user.instance_of?(UNIXUser)
        raise "unix_user_to_user :user argument just be a UNIXUser object."
      end
      
      if user.removed?
        raise "unix_user_to_user :user has been removed."
      end
      
      remove_unix_groups = args[:remove_unix_groups] || false
      
      # User attributes.
      username = user.username
      container = user.container
      primary_group = user.primary_group
      disabled = user.disabled?
      rid = user.rid
      first_name = user.first_name
      initials = user.initials
      middle_name = user.middle_name
      surname = user.surname
      script_path = user.script_path
      profile_path = user.profile_path
      local_path = user.local_path
      local_drive = user.local_drive
      password = user.password
      must_change_password = user.must_change_password?
      groups = user.groups.clone
      removed_groups = user.removed_groups.clone
      loaded = user.loaded?
      
      # Destroy the user now that we have its information.
      container.destroy_user user
      
      # If the user was destroyed and we got this far, we need to remove
      # any of its UNIX attributes in Active Directory directly. We do need
      # to make sure it is actually there first of course.
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      found = @ldap.search(:base => user.distinguished_name,
                           :filter => user_filter,
                           :scope => Net::LDAP::SearchScope_BaseObject,
                           :return_result => false)
      
      unless found == false
        ops = [
          [:replace, :loginShell, nil],
          [:replace, :unixHomeDirectory, nil],
          [:replace, :msSFU30NisDomain, nil],
          [:replace, :gecos, nil],
          [:replace, :unixUserPassword, nil],
          [:replace, :shadowExpire, nil],
          [:replace, :shadowFlag, nil],
          [:replace, :shadowInactive, nil],
          [:replace, :shadowLastChange, nil],
          [:replace, :shadowMax, nil],
          [:replace, :shadowMin, nil],
          [:replace, :shadowWarning, nil],
          [:replace, :gidNumber, nil],
          [:replace, :uidNumber, nil]
        ]
        
        @ldap.modify :dn => user.distinguished_name, :operations => ops
        check_ldap_result
      end
      
      user = User.new :username => username, :container => container,
                      :primary_group => primary_group, :disabled => disabled,
                      :rid => rid
      
      # Set the user to loaded if it was loaded orginally. This sets the
      # modified attribute to false, but the actions below will ensure the
      # modified attribute is actually true when we are done, which is required
      # in order to update the attributes in Active Directory through AD#sync.
      user.set_loaded if loaded
      
      # Set other User attributes.
      user.first_name = first_name
      user.initials = initials
      user.middle_name = middle_name
      user.surname = surname
      user.script_path = script_path
      user.profile_path = profile_path
      
      # Figure out the Windows home directory type attributes.
      if local_path && local_drive
        user.connect_drive_to local_drive, local_path
      elsif local_path
        user.local_path = local_path
      end
      
      user.password = password
      
      if must_change_password
        user.force_change_password
      end
      
      (groups + removed_groups).each do |group_member|
        user.add_group group_member
      end
      
      removed_groups.each do |group_member|
        user.remove_group group_member
      end
      
      # An extra step to remove any UNIXGroup objects if that was requested.
      if remove_unix_groups
        user.groups.clone.each do |group|
          user.remove_group group if group.instance_of?(UNIXGroup)
        end
      end
      
      user
    end
    
    # Returns an Array of all Group and UNIXGroup objects in the AD.
    def groups
      all_groups = []
      
      @containers.each do |container|
        all_groups += container.groups
      end
      
      all_groups
    end
    
    # Returns an Array of all removed Group and UNIXGroup objects in the AD.
    def removed_groups
      all_removed_groups = []
      
      @containers.each do |container|
        all_removed_groups += container.removed_groups
      end
      
      # We also need to check removed Containers too because they can have
      # removed groups too.
      @removed_containers.each do |container|
        all_removed_groups += container.removed_groups
      end
      
      all_removed_groups
    end
    
    # Find a Group or UNIXGroup in the AD object. The first argument is a
    # boolean that indicates if the search should be for removed groups. It is
    # optional and defaults to false. The second required argument is a block.
    # The block is passed each Group and UNIXGroup object and contains the
    # desired testing expression. Attributes for either Group or UNIXGroup
    # objects can be used without worrying about the accessor methods existing.
    # Examples follow:
    #
    # * Find a Group or UNIXGroup by name:
    #  find_group { |group| group.name == "name" }
    # * Find a UNIXGroup by gid:
    #  find_group { |group| group.gid == 1002 }
    # * Find a removed Group or UNIXGroup by name:
    #  find_group(true) { |group| group.name == "name" }
    # * Find a removed UNIXGroup by gid:
    #  find_group(true) { |group| group.gid == 1002 }
    #
    # If no block is given the method returns nil. If the Group or UNIXGroup is
    # not found, the method also returns nil, otherwise the Group or UNIXGroup
    # object found is returned.
    #
    # There are convenient find_group_by_<attribute> methods defined that take
    # care of the example cases here as well, but this method allows any block
    # test to be given.
    #
    # === Parameter Types
    #
    # * removed [boolean]
    # * [block]
    def find_group(removed = false)
      if block_given?
        if removed
          search_groups = removed_groups
        else
          search_groups = groups
        end
        
        found = search_groups.find do |group|
          begin
            yield group
          rescue NoMethodError
          end
        end
        
        return found if found
        return nil
      end
      
      return nil
    end
    
    # Find a Group or UNIXGroup in the AD by name. The search is
    # case-insensitive. The Group or UNIXGroup is returned if found, otherwise
    # nil is returned. Specify the second argument as true if you wish to
    # search for removed Group or UNIXGroup objects.
    #
    # === Parameter Types
    #
    # * name [String]
    # * removed [boolean]
    def find_group_by_name(name, removed = false)
      find_group removed do |group|
        group.name.downcase == name.downcase
      end
    end
    
    # Find a Group or UNIXGroup in the AD by RID. The Group or UNIXGroup is
    # returned if found, otherwise nil is returned. Specify the second argument
    # as true if you wish to search for removed Group or UNIXGroup objects.
    #
    # === Parameter Types
    #
    # * rid [integer]
    # * removed [boolean]
    def find_group_by_rid(rid, removed = false)
      find_group(removed) { |group| group.rid == rid }
    end
    
    # Find a UNIXGroup in the AD by GID. The UNIXGroup is returned if found,
    # otherwise nil is returned. Specify the second argument as true if you
    # wish to search for removed UNIXGroup objects.
    #
    # === Parameter Types
    #
    # * gid [integer]
    # * removed [boolean]
    def find_group_by_gid(gid, removed = false)
      find_group(removed) { |group| group.gid == gid }
    end
    
    # Find a Group or UNIXGroup in the AD by distinguished name. The search is
    # case-insensitive. The Group or UNIXGroup is returned if found, otherwise
    # nil is returned. Specify the second argument as true if you wish to
    # search for removed Group or UNIXGroup objects.
    #
    # === Parameter Types
    #
    # * dn [String]
    # * removed [boolean]
    def find_group_by_dn(dn, removed = false)
      find_group removed do |group|
        group.distinguished_name.downcase == dn.downcase
      end
    end
    
    # Convert a Group to a UNIXGroup. This method returns the new UNIXGroup
    # if successful, otherwise there will be a RuntimeError somewhere first.
    # The original Group is destroyed with Container#destroy_group and a new
    # UNIXGroup is created with the same information. New UNIX attributes will
    # be added to Active Directory. Any external references to the old Group
    # should be discarded and replaced with the new UNIXGroup object returned.
    # Supported arguments follow:
    #
    # * :group => The Group to convert to a UNIXGroup [required]
    # * :gid => The UNIXGroup GID attribute [required]
    # * :nis_domain => The UNIXGroup NIS domain attribute [default "radum"]
    #
    # The :gid argument specifies the UNIX GID value of the UNIXGroup. The
    # :nis_domain defaults to "radum". The use of an NIS domain is not
    # strictly required as one could simply set the right attributes in Active
    # Directory and use LDAP on clients to access that data, but specifying an
    # NIS domain allows for easy editing of UNIX attributes using the GUI tools
    # in Windows, thus the use of a default value.
    #
    # === Parameter Types
    #
    # * :group [Group]
    # * :gid [integer]
    # * :nis_domain [String]
    #
    # If the :group argument is not a Group object, a RuntimeError is raised.
    # If the Group has already been removed a RuntimeError is raised.
    # The :gid argument is also checked first in case it already is in use
    # so that the original group is not destroyed by accident due to an error.
    # Note that Container#destroy_group checks to make sure the group is not
    # the primary Windows group for any User or UNIXUser first, so the :group
    # must not be the primary Windows group for any users. If the group is
    # someone's primary Windows group a RuntimeError is raised. You will have
    # to modify it by hand in Active Directory if you want to convert it. The
    # primary Windows group check is not done for all users in Active Directory
    # because it is safe to convert unless RADUM thinks the Group is one of
    # its User or UNIXUser object's primary Windows group. In that specific
    # case, you'll have to modify the group in Active Directory by hand
    # unfortunately.
    #
    # In this case, unlike when simply creating a UNIXGroup object, all GIDs
    # are checked, including those already in Active Directory.
    #
    # No changes to the Group happen until AD#sync is called.
    def group_to_unix_group(args = {})
      group = args[:group]
      
      # Make sure we are working with a Group object only.
      unless group.instance_of?(Group)
        raise "group_to_unix_group :group argument just be a Group object."
      end
      
      if group.removed?
        raise "group_to_unix_group :group has been removed."
      end
      
      gid = args[:gid]
      all_gids = load_ldap_gids
      
      # The GID must be unique.
      if (all_gids + @gids).include?(gid)
        raise "GID #{gid} is already in use in the directory."
      end
      
      nis_domain = args[:nis_domain]
      # Group attributes.
      name = group.name
      container = group.container
      type = group.type
      rid = group.rid
      users = group.users.clone
      groups = group.groups.clone
      removed_users = group.removed_users.clone
      removed_groups = group.removed_groups.clone
      loaded = group.loaded?
      
      # Destroy the group now that we have its information. This will fail if
      # the group is someone's primary Windows group from the RADUM perspective
      # because of the logic I have to employ, but it is fine if the group is
      # some other user account's primary Windows group that RADUM doesn't
      # know about.
      container.destroy_group group
      
      group = UNIXGroup.new :name => name, :container => container,
                            :type => type, :rid => rid, :gid => gid,
                            :nis_domain => nis_domain
      
      # Set the group to loaded if it was loaded orginally. This sets the
      # modified attribute to false, but the actions below will ensure the
      # modified attribute is actually true when we are done, which is required
      # in order to update the attributes in Active Directory through AD#sync.
      group.set_loaded if loaded
      
      (users + removed_users).each do |user_member|
        group.add_user user_member
      end
      
      removed_users.each do |user_member|
        group.remove_user user_member
      end
      
      (groups + removed_groups).each do |group_member|
        group.add_group group_member
      end
      
      removed_groups.each do |group_member|
        group.remove_group group_member
      end
      
      group
    end
    
    # Convert a UNIXGroup to a Group. This method returns the new Group
    # if successful, otherwise there will be a RuntimeError somewhere first.
    # The original UNIXGroup is destroyed with Container#destroy_group and a
    # new Group is created with the same information where applicable. Old
    # UNIX attributes will be removed from Active Directory if possible
    # immediately (not waiting on AD#sync because AD#sync will think this is
    # now only a Group object with no UNIX attributes). Any external references
    # to the old UNIXGroup should be discarded and replaced with the new Group
    # object returned. Supported arguments follow:
    #
    # * :group => The UNIXGroup to convert to a Group [required]
    # * :remove_unix_users => Remove UNIXUser object members [default false]
    # 
    # The :group argument is the UNIXGroup to convert. If the :group argument
    # is not a UNIXGroup object, a RuntimeError is raised. If the UNIXGroup
    # has already been removed a RuntimeError is raised. The :remove_unix_users
    # argument is a boolean flag that determines if UNIXUser objects who were
    # members of the UNIXGroup from the Windows perspective should be removed
    # as members when converting to a Group object. UNIXUser objects are
    # members from the Windows perspective as well by default because they are
    # members from the UNIX perspective. This is the default behavior in
    # RADUM. The default action is to not remove their Windows user
    # memberships when converting a UNIXGroup to a Group.
    #
    # === Parameter Types
    #
    # * :group [UNIXGroup]
    # * :remove_unix_users [boolean]
    #
    # Note that Container#destroy_group checks to make sure the group is not
    # the primary Windows group or UNIX main group for any User or UNIXUser,
    # so the :group must not be the primary Windows group or UNIX main group
    # for any users. If the group is someone's primary Windows group or UNIX
    # main group a RuntimeError will be raised. You will have to modify it by
    # hand in Active Directory if you want to convert it. The UNIX main group
    # condition is checked for all users in Active Directory before attempting
    # to use Container#destroy_group to ensure the conversion is safe. The
    # primary Windows group check is not done for all users in Active Directory
    # because it is safe to convert unless RADUM thinks the UNIXGroup
    # is one of its User or UNIXUser object's primary Windows group. In that
    # specific case, you'll have to modify the group in Active Directory by
    # hand unfortunately.
    #
    # UNIX attributes are removed from Active Directory immedately if it is
    # actually possible to destroy the UNIXGroup properly without waiting for
    # AD#sync to be called.
    def unix_group_to_group(args = {})
      group = args[:group]
      
      # Make sure we are working with a UNIXGroup object only.
      unless group.instance_of?(UNIXGroup)
        raise "unix_group_to_group :group argument just be a UNIXGroup object."
      end
      
      if group.removed?
        raise "unix_group_to_group :group has been removed."
      end
      
      remove_unix_users = args[:remove_unix_users] || false
      
      # Group attributes.
      name = group.name
      container = group.container
      type = group.type
      rid = group.rid
      users = group.users.clone
      groups = group.groups.clone
      removed_users = group.removed_users.clone
      removed_groups = group.removed_groups.clone
      loaded = group.loaded?
      
      # Make sure the group is not someone's UNIX main group for all users
      # in Active Directory before trying to destroy the group. The
      # Container#destroy_group method only checks for objects in RADUM
      # itself.
      if ldap_is_unix_main_group?(group)
        raise "unix_group_to_group :group is someone's UNIX main group."
      end
      
      # Destroy the group now that we have its information. This will fail if
      # the group is someone's primary Windows group from the RADUM perspective
      # because of the logic I have to employ, but it is fine if the group is
      # some other user account's primary Windows group that RADUM doesn't
      # know about.
      container.destroy_group group
      
      # If the group was destroyed and we got this far, we need to remove
      # any of its UNIX attributes in Active Directory directly. We do need
      # to make sure it is actually there first of course.
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
      found = @ldap.search(:base => group.distinguished_name,
                           :filter => group_filter,
                           :scope => Net::LDAP::SearchScope_BaseObject,
                           :return_result => false)
      
      unless found == false
        ops = [
          [:replace, :msSFU30NisDomain, nil],
          [:replace, :unixUserPassword, nil],
          [:replace, :memberUid, nil],
          [:replace, :msSFU30PosixMember, nil]
        ]
        
        @ldap.modify :dn => group.distinguished_name, :operations => ops
        check_ldap_result
      end
      
      group = Group.new :name => name, :container => container,
                        :type => type, :rid => rid
      
      # Set the group to loaded if it was loaded orginally. This sets the
      # modified attribute to false, but the actions below will ensure the
      # modified attribute is actually true when we are done, which is required
      # in order to update the attributes in Active Directory through AD#sync.
      group.set_loaded if loaded
      
      (users + removed_users).each do |user_member|
        group.add_user user_member
      end
      
      removed_users.each do |user_member|
        group.remove_user user_member
      end
      
      (groups + removed_groups).each do |group_member|
        group.add_group group_member
      end
      
      removed_groups.each do |group_member|
        group.remove_group group_member
      end
      
      # An extra step to remove any UNIXUser objects if that was requested.
      if remove_unix_users
        group.users.clone.each do |user|
          group.remove_user user if user.instance_of?(UNIXUser)
        end
      end
      
      group
    end
      
    # Load all user and group objects in Active Directory that are in the AD
    # object's Containers. This automatically creates User, UNIXUser, Group,
    # and UNIXGroup objects as needed and sets all of their attributes
    # correctly. This can be used to initialize a program using the RADUM 
    # module for account management work.
    #
    # User objects are not created if their primary Windows group is not found
    # during the load. UNIXUser objects are not created if their UNIX main group
    # is not found during the load. Warning messages are printed in each
    # case. Make sure all required Containers are in the AD before loading
    # data from Active Directory to avoid this problem.
    #
    # You generally should call AD#load to ensure the RADUM system has a valid
    # representation of the Active Directory objects. You can call AD#sync
    # without calling AD#load first, but your object values are authoritative.
    # Unless you set every attribute correctly, unset object attributes will
    # overwrite current values in Active Directory. Note that AD#sync will
    # not touch Active Directory group memberships it does not know about
    # explicitly, so AD#sync will not remove group and user memberships in
    # groups that were not explicitly removed in RADUM. The general RADUM
    # pattern is:
    #
    # * AD.new(...)
    # * Container.new(...) [for any Containers of interest]
    # * AD#load()
    # * Create, update, or remove existing loaded objects.
    # * AD#sync()
    #
    # This methods will sliently ignore objects that already exist in the AD
    # object unless the Logger default_level is set to LOG_DEBUG. Therefore,
    # it is possible to load new Container objects after calling this method
    # previously to create new objects. Anything that previously exists will
    # be ignored.
    def load
      RADUM::logger.log("[AD #{self.root}] entering load()", LOG_DEBUG)
      # This method can be called more than once. After loading users and
      # groups, we just want to work with those after they are created. This
      # allows the method to be called more than once.
      loaded_users = []
      loaded_groups = []
      # Find all the groups first. We might need one to represent the main
      # group of a UNIX user.
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
      
      @containers.each do |container|
        @ldap.search(:base => container.distinguished_name,
                     :filter => group_filter,
                     :scope => Net::LDAP::SearchScope_SingleLevel) do |entry|
          attr = group_ldap_entry_attr(entry)
          
          # Skip any Group or UNIXGroup objects that already exist (have this
          # :name attribute).
          if find_group_by_name(attr[:name])
            RADUM::logger.log("\tNot loading group <#{attr[:name]}>: already" +
                              " exists.", LOG_DEBUG)
            next
          end
          
          # Note that groups add themselves to their container.
          unless attr[:gid].nil?
            attr[:nis_domain] = "radum" unless attr[:nis_domain]
            group = UNIXGroup.new :name => attr[:name], :container => container,
                                  :gid => attr[:gid], :type => attr[:type],
                                  :nis_domain => attr[:nis_domain],
                                  :rid => attr[:rid]
            group.unix_password = attr[:unix_password] if attr[:unix_password]
            loaded_groups.push group
          else
            group = Group.new :name => attr[:name], :container => container,
                              :type => attr[:type], :rid => attr[:rid]
            loaded_groups.push group
          end 
        end
      end
      
      # Find all the users. The UNIX main group must be set for UNIXUser
      # objects, so it will be necessary to search for that.
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @containers.each do |container|
        @ldap.search(:base => container.distinguished_name,
                     :filter => user_filter,
                     :scope => Net::LDAP::SearchScope_SingleLevel) do |entry|
          attr = user_ldap_entry_attr(entry)
          
          # Skip any User or UNIXUser objects that already exist (have this
          # :username attribute).
          if find_user_by_username(attr[:username])
            RADUM::logger.log("\tNot loading user <#{attr[:username]}>:" +
                              " already exists.", LOG_DEBUG)
            next
          end
          
          # Note that users add themselves to their container. We have to have
          # found the primary_group already, or we can't make the user. The
          # primary group is important information, but it is stored as a RID
          # value in the primaryGroupID AD attribute. The group membership
          # it defines is defined nowhere else however. We will print a warning
          # for any users skipped. This is why the AD object automatically
          # adds a cn=Users container.
          if attr[:primary_group]
            unless attr[:uid].nil? || attr[:gid].nil?
              if unix_main_group = find_group_by_gid(attr[:gid])
                attr[:nis_domain] = "radum" unless attr[:nis_domain]
                user = UNIXUser.new :username => attr[:username],
                                    :container => container,
                                    :primary_group => attr[:primary_group],
                                    :uid => attr[:uid],
                                    :unix_main_group => unix_main_group,
                                    :shell => attr[:shell],
                                    :home_directory => attr[:home_directory],
                                    :nis_domain => attr[:nis_domain],
                                    :disabled => attr[:disabled?],
                                    :rid => attr[:rid]
                user.distinguished_name = attr[:distinguished_name]
                user.first_name = attr[:first_name] if attr[:first_name]
                user.initials = attr[:initials] if attr[:initials]
                user.middle_name = attr[:middle_name] if attr[:middle_name]
                user.surname = attr[:surname] if attr[:surname]
                user.script_path = attr[:script_path] if attr[:script_path]
                user.profile_path = attr[:profile_path] if attr[:profile_path]
                
                if attr[:local_drive] && attr[:local_path]
                  user.connect_drive_to(attr[:local_drive], attr[:local_path])
                elsif attr[:local_path]
                  user.local_path = attr[:local_path]
                end
                
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
                
                if attr[:must_change_password?]
                  user.force_change_password
                end
                
                loaded_users.push user
              else
                RADUM::logger.log("Warning: Main UNIX group could not be " +
                                  "found for: " + attr[:username], LOG_NORMAL)
                RADUM::logger.log("Not loading #{attr[:username]}.", LOG_NORMAL)
              end
            else
              user = User.new :username => attr[:username],
                              :container => container,
                              :primary_group => attr[:primary_group],
                              :disabled => attr[:disabled?],
                              :rid => attr[:rid]
              user.distinguished_name = attr[:distinguished_name]
              user.first_name = attr[:first_name] if attr[:first_name]
              user.initials = attr[:initials] if attr[:initials]
              user.middle_name = attr[:middle_name] if attr[:middle_name]
              user.surname = attr[:surname] if attr[:surname]
              user.script_path = attr[:script_path] if attr[:script_path]
              user.profile_path = attr[:profile_path] if attr[:profile_path]
              
              if attr[:local_drive] && attr[:local_path]
                user.connect_drive_to(attr[:local_drive], attr[:local_path])
              elsif attr[:local_path]
                user.local_path = attr[:local_path]
              end
              
              if attr[:must_change_password?]
                user.force_change_password
              end
              
              loaded_users.push user
            end
          else
            RADUM::logger.log("Warning: Windows primary group not found for: " +
                              attr[:username], LOG_NORMAL)
            RADUM::logger.log("Not loading #{attr[:username]}.", LOG_NORMAL)
          end
        end
      end
      
      # Add users to groups, which also adds the groups to the user, etc. The
      # Windows primary_group was taken care of when creating the users
      # previously. This can happen even if this method is called multiple
      # times because it is safe to add users to groups (and vice versa)
      # more than once. If the membership already exists, nothing happens.
      # Note that in this case, we do have to process all groups again in case
      # some of the new users are in already processed groups.
      #
      # Here it is key to process all groups, even if they were already
      # loaded once.
      groups.each do |group|
        begin
          # Note that this takes care of the case where a group was created
          # and then AD#load is called before AD#sync. In that case, the group
          # is not even in Active Directory yet and the pop method call will
          # not be possible because it does not exist. There are other ways
          # to check this, but I don't really care if it was not found because
          # I assume the user knows what they are doing if they do this type
          # of pattern.
          entry = @ldap.search(:base => group.distinguished_name,
                               :filter => group_filter,
                               :scope => Net::LDAP::SearchScope_BaseObject).pop
          
          entry.member.each do |member|
            # Groups can have groups or users as members, unlike UNIX where
            # groups cannot contain group members.
            member_group = find_group_by_dn(member)
            
            if member_group
              group.add_group member_group
            end
            
            member_user = find_user_by_dn(member)
            
            if member_user
              group.add_user member_user
            end
          end
        rescue NoMethodError
        end
      end
      
      # Set all users and groups as loaded. This has to be done last to make
      # sure the modified attribute is correct. The modified attribute needs
      # to be false, and it is hidden from direct access by the set_loaded
      # method. In this case "all users and groups" means ones we explicitly
      # processed because this method can be called more than once. If the
      # original object was loaded, but then modified, we don't want to reset
      # the modified attribute as well. We also don't want to set the loaded
      # attribute and reset the modified attribute for objects that were
      # created after an initial call to this method and were skipped on
      # later calls.
      #
      # Here it is key to only touch things explicitly loaded in this call.
      loaded_groups.each do |group|
        group.set_loaded
      end
        
      loaded_users.each do |user|
        user.set_loaded
      end
      
      RADUM::logger.log("[AD #{self.root}] exiting load()", LOG_DEBUG)
    end
    
    # Load the next free UID value. This is a convenience method that allows
    # one to find the next free UID value. This method returns the next free
    # UID value found while searching from the AD root and any current UID
    # values for UNIXUser objects that might not be in the Active Directory yet.
    # If nothing is found, the min_uid attribute is returned.
    def load_next_uid
      all_uids = load_ldap_uids
      next_uid = 0
      
      # This accounts for any GIDs that might not be in Active Directory yet
      # as well.
      (all_uids + @uids).uniq.sort.each do |uid|
        if next_uid == 0 || next_uid + 1 == uid
          next_uid = uid
        else
          break
        end
      end
      
      if next_uid == 0
        @min_uid
      else
        next_uid + 1
      end
    end
    
    # Load the next free GID value. This is a convenince method that allows
    # one to find the next free GID value. This method returns the next free
    # GID value found while searching from the AD root and any current GID
    # values for UNIXGroup objects that might not be in the Active Directory
    # yet. If nothing is found, the min_gid attribute is returned.
    def load_next_gid
      all_gids = load_ldap_gids
      next_gid = 0
      
      # This accounts for any GIDs that might not be in Active Directory yet
      # as well.
      (all_gids + @gids).uniq.sort.each do |gid|
        if next_gid == 0 || next_gid + 1 == gid
          next_gid = gid
        else
          break
        end
      end
      
      if next_gid == 0
        @min_gid
      else
        next_gid + 1
      end
    end
    
    # Synchronize all modified Container, User, UNIXUser, Group, and UNIXGroup
    # objects to Active Directory. This will create entries as needed after
    # checking to make sure they do not already exist. New attributes will be
    # added, unset attributes will be removed, and modified attributes will be
    # updated automatically. Removed objects will be deleted from Active
    # Directory.
    #
    # You generally should call AD#load to ensure the RADUM system has a valid
    # representation of the Active Directory objects. You can call AD#sync
    # without calling AD#load first, but your object values are authoritative.
    # Unless you set every attribute correctly, unset object attributes will
    # overwrite current values in Active Directory. Note that AD#sync will
    # not touch Active Directory group memberships it does not know about
    # explicitly, so AD#sync will not remove group and user memberships in
    # groups that were not explicitly removed in RADUM. The general RADUM
    # pattern is:
    #
    # * AD.new(...)
    # * Container.new(...) [for any Containers of interest]
    # * AD#load()
    # * Create, update, or remove existing loaded objects.
    # * AD#sync()
    def sync
      RADUM::logger.log("[AD #{self.root}] entering sync()", LOG_DEBUG)
      
      # First, delete any users that have been removed from a container here.
      # We need to remove users first because a group cannot be removed if
      # a user has it as their primary Windows group. Just in case, we remove
      # the removed users first. The same applies if the group is some other
      # user's UNIX main group. The code in this module makes sure that doesn't
      # happen for objects it knows about, but there could be others in Active
      # Directory the module does not know about.
      removed_users.each do |user|
        delete_user user
      end
      
      # Second, remove any groups that have been removed from a contianer here.
      removed_groups.each do |group|
        # This method checks if the group is some other user's primary Windows
        # group by searching the entire Active Directory. A group cannot be
        # removed if it is any user's primary Windows group. The same applies
        # if the group is some other user's UNIX main group. The code in this
        # module makes sure that doesn't happen for objects it knows about, but
        # there could be others in Active Directory the module does not know
        # about.
        delete_group group
      end
      
      # Third, remove any containers that have been removed. This can only be
      # done after all the user and group removals hae been dealt with. This
      # can still fail if there are any objects in Active Directory inside of
      # the container (such as another container).  Note that the
      # AD.remove_container method makes sure that a container is not removed
      # if it contains another container in the first place.
      @removed_containers.each do |container|
        delete_container container
      end
      
      # Fourth, create any containers or organizational units that do not
      # already exist.
      @containers.each do |container|
        # This method only creates containers that do not already exist. Since
        # containers are not loaded directly at first, their status is directly
        # tested in the method.
        create_container container
      end
      
      # Fifth, make sure any groups that need to be created are added to Active
      # Directory.
      groups.each do |group|
        # This method checks if the group actually needs to be created or not.
        create_group group
      end
      
      # Sixth, make sure any users that need to be created are added to Active
      # Directory.
      users.each do |user|
        # This method checks if the user actually needs to be created or not.
        create_user user
      end
      
      # Seventh, update any modified attributes on each group.
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
      
      RADUM::logger.log("[AD #{self.root}] exiting sync()", LOG_DEBUG)
    end
    
    # The String representation of the AD object.
    def to_s
      "AD [#{@root} #{@server}:#{@port}]"
    end
    
    private
    
    # Unpack a RID from the SID value in the LDAP objectSid attribute for a
    # user or group in Active Directory.
    #
    # === Parameter Types
    #
    # * sid [binary LDAP attribute value]
    def sid2rid_int(sid)
      sid.unpack("qV*").pop.to_i
    end
    
    # Convert a string to UTF-16LE. For ASCII characters, the result should be
    # each character followed by a NULL, so this is very easy. Windows expects
    # a UTF-16LE string for the unicodePwd attribute. Note that the password
    # Active Directory is expecting for the unicodePwd attribute has to be
    # explicitly quoted.
    #
    # === Parameter Types
    #
    # * str [String]
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
    
    # Return an array of all GID values in Active Directory.
    def load_ldap_gids
      all_gids = []
      group_filter = Net::LDAP::Filter.eq("objectclass", "group")
    
      @ldap.search(:base => @root, :filter => group_filter) do |entry|
        begin
          gid = entry.gidNumber.pop.to_i
          all_gids.push gid
        rescue NoMethodError
        end
      end
      
      all_gids
    end
    
    # Return an array of all UID values in Active Directory.
    def load_ldap_uids
      all_uids = []
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @ldap.search(:base => @root, :filter => user_filter) do |entry|
        begin
          uid = entry.uidNumber.pop.to_i
          all_uids.push uid
        rescue NoMethodError
        end
      end
      
      all_uids
    end
    
    # Return a hash with an Active Directory group's base LDAP attributes. The
    # key is the RADUM group attribute name and the value is the computed value
    # from the group's attributes in Active Directory.
    #
    # === Parameter Types
    #
    # * entry [String]
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
    #
    # === Parameter Types
    #
    # * entry [String]
    def user_ldap_entry_attr(entry)
      attr = {}
      # These are attributes that might be empty. If they are empty,
      # a NoMethodError exception will be raised. We have to check each
      # individually and set an initial indicator value (nil). All the
      # other attributes should exist and do not require this level of
      # checking.
      attr[:first_name] = nil
      attr[:initials] = nil
      attr[:middle_name] = nil
      attr[:surname] = nil
      attr[:script_path] = nil
      attr[:profile_path] = nil
      attr[:local_path] = nil
      attr[:local_drive] = nil
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
        attr[:initials] = entry.initials.pop
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
        attr[:script_path] = entry.scriptPath.pop
      rescue NoMethodError
      end
      
      begin
        attr[:profile_path] = entry.profilePath.pop
      rescue NoMethodError
      end
      
      begin
        attr[:local_path] = entry.homeDirectory.pop
      rescue NoMethodError
      end
      
      begin
        attr[:local_drive] = entry.homeDrive.pop
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
      
      attr[:disabled?] = (entry.userAccountControl.pop.to_i ==
                         UF_NORMAL_ACCOUNT + UF_ACCOUNTDISABLE ? true : false)
      attr[:must_change_password?] = (entry.pwdLastSet.pop.to_i == 0)
      attr[:primary_group] = find_group_by_rid(entry.primaryGroupID.pop.to_i)
      attr[:rid] = sid2rid_int(entry.objectSid.pop)
      attr[:username] = entry.sAMAccountName.pop
      attr[:distinguished_name] = entry.distinguishedName.pop
      return attr
    end
    
    # Check the LDAP operation result code for an error message.
    def check_ldap_result
      unless @ldap.get_operation_result.code == 0
        RADUM::logger.log("LDAP ERROR: " + @ldap.get_operation_result.message,
                          LOG_NORMAL)
        RADUM::logger.log("[Error code: " +
                          @ldap.get_operation_result.code.to_s + "]",
                          LOG_NORMAL)
      end
    end
    
    # Delete a Container from Active Directory. There isn't much we can check
    # except trying to delete it.
    #
    # === Parameter Types
    #
    # * container [Container]
    def delete_container(container)
      RADUM::logger.log("[AD #{self.root}]" +
                        " delete_container(<#{container.name}>)", LOG_DEBUG)
      @ldap.delete :dn => container.distinguished_name
      check_ldap_result
      # Now that the Container has been removed from Active Directory, it is
      # destroyed from the AD it belongs to. There is no need to care about
      # it anymore. Any Container that can be deleted from Active Directory
      # can be destroyed.
      RADUM::logger.log("\tDestroying container <#{container.name}>.",
                        LOG_DEBUG)
      destroy_container container
    end
    
    # Create a Container in Active Directory. Each Container is searched for
    # directly and created if it does not already exist. This method also
    # automatically creates parent containers as required. This is safe to
    # do, even if one of those was also passed to this method later (since it
    # would then be found).
    #
    # === Parameter Types
    #
    # * container [Container]
    def create_container(container)
      RADUM::logger.log("[AD #{self.root}]" +
                        " create_container(<#{container.name}>)", LOG_DEBUG)
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
          RADUM::logger.log("SYNC ERROR: " + container.name +
                            " ( #{current_name}) - unknown Container type.",
                            LOG_NORMAL)
          return
        end
        
        container_filter = Net::LDAP::Filter.eq("objectclass", type)
        # The return value will be false explicitly if the search fails,
        # otherwise it will be an array of entries. Therefore it is important
        # to check for false explicitly for a failure. A failure indicates
        # that the container needs to be created.
        found = @ldap.search(:base => distinguished_name,
                             :filter => container_filter,
                             :scope => Net::LDAP::SearchScope_BaseObject,
                             :return_result => false)
        
        if found == false
          RADUM::logger.log("\t#{distinguished_name} not found - creating.",
                            LOG_DEBUG)
          
          # Note that all the attributes need to be strings in the attr hash.
          if type == "organizationalUnit"
            attr = {
              :name => current_name.split(/,/)[0].gsub(/[Oo][Uu]=/, ""),
              :objectclass => ["top", "organizationalUnit"]
            }
          elsif type == "container"
            name = current_name.split(/,/)[0].gsub(/[Cc][Nn]=/, "")
            
            attr = {
              :name => name,
              :objectclass => ["top", "container"]
            }
          else
            RADUM::logger.log("SYNC ERROR: " + container.name +
                              " ( #{current_name}) - unknown Container type.",
                              LOG_NORMAL)
            return
          end
          
          @ldap.add :dn => distinguished_name, :attributes => attr
          check_ldap_result
        else
          RADUM::logger.log("\t#{distinguished_name} found - not creating.",
                            LOG_DEBUG)
        end
      end
    end
    
    # Determine if the group is anyone's primary Windows group in Active
    # Directory. Returns true if the group is anyone's primary Windows group,
    # false otherwise. This works for Group and UNIXGroup objects.
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def ldap_is_primary_windows_group?(group)
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      @ldap.search(:base => @root, :filter => user_filter) do |entry|
        rid = entry.primaryGroupID.pop.to_i
        return true if rid == group.rid
      end
      
      false
    end
    
    # Determine if the group is anyone's UNIX main group in Active Directory.
    # Returns true if the group is anyone's UNIX main group, false otherwise.
    # This works for UNIXGroup objects and returns false for Group objects.
    #
    # === Parameter Types
    #
    # * group [UNIXGroup]
    def ldap_is_unix_main_group?(group)
      user_filter = Net::LDAP::Filter.eq("objectclass", "user")
      
      if group.instance_of?(UNIXGroup)
        @ldap.search(:base => @root, :filter => user_filter) do |entry|
          begin
            gid = entry.gidNumber.pop.to_i
            return true if gid == group.gid
          rescue NoMethodError
          end
        end
      end
      
      false
    end
    
    # Delete a Group or UNIXGroup from Active Directory.
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def delete_group(group)
      RADUM::logger.log("[AD #{self.root}]" +
                        " delete_group(<#{group.name}>)", LOG_DEBUG)
      # First check to make sure the group is not the primary Windows group
      # or UNIX main group for any user in Active Directory. We could probably
      # rely on the attempt to delete the group failing, but I don't like doing
      # that. Yes, it is much less efficient this way, but removing a group is
      # not very common in my experience. Also note that this would probably not
      # fail for a UNIX main group because that's pretty much "tacked" onto
      # the standard Windows Active Directory logic (at least, I have been
      # able to remove a group that was someone's UNIX main group before, but
      # not their primary Windows group).
      found_primary = ldap_is_primary_windows_group?(group)
      found_unix = ldap_is_unix_main_group?(group)
      
      unless found_primary || found_unix
        RADUM::logger.log("\tDeleted group <#{group.name}>.", LOG_DEBUG)
        @ldap.delete :dn => group.distinguished_name
        check_ldap_result
        # Now that the group has been removed from Active Directory, it is
        # destroyed from the Container it belongs to. There is no need to
        # care about it anymore.
        RADUM::logger.log("\tDestroying group <#{group.name}>.", LOG_DEBUG)
        group.container.destroy_group group
      else
        RADUM::logger.log("\tCannot delete group <#{group.name}>:", LOG_DEBUG)
        
        if found_primary
          RADUM::logger("\t<#{group.name}> is the primary Windows group for a" +
                        " user in Active Directory.", LOG_DEBUG)
        end
        
        if found_unix
          RADUM::logger.log("\t<#{group.name}> is the UNIX main group for a" +
                            " user in Active Directory.", LOG_DEBUG)
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
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def create_group(group)
      unless group.loaded?
        group_filter = Net::LDAP::Filter.eq("objectclass", "group")
        # The return value will be false explicitly if the search fails,
        # otherwise it will be an array of entries. Therefore it is important
        # to check for false explicitly for a failure. A failure indicates
        # that the group needs to be created.
        found = @ldap.search(:base => group.distinguished_name,
                             :filter => group_filter,
                             :scope => Net::LDAP::SearchScope_BaseObject,
                             :return_result => false)
        
        # The group should not already exist of course. This is to make sure
        # it is not already there in the case it was manually created but
        # matches a group that already exists.
        if found == false
          RADUM::logger.log("[AD #{self.root}]" +
                            " create_group(<#{group.name}>)", LOG_DEBUG)
          
          # Note that all the attributes need to be strings in this hash.
          attr = {
            :groupType => group.type.to_s,
            # All groups are of the objectclasses "top" and "group".
            :objectclass => ["top", "group"],
            :sAMAccountName => group.name
          }
          
          attr.merge!({
            :gidNumber => group.gid.to_s,
            :msSFU30Name => group.name,
            :msSFU30NisDomain => group.nis_domain,
            :unixUserPassword => group.unix_password
          }) if group.instance_of?(UNIXGroup)
          
          if group.instance_of?(UNIXGroup)
            attr.merge!({ :description => "UNIX group #{group.name}" })
          else
            attr.merge!({ :description => "Group #{group.name}" })
          end
          
          RADUM::logger.log("\n" + attr.to_yaml + "\n\n", LOG_DEBUG)
          @ldap.add :dn => group.distinguished_name, :attributes => attr
          check_ldap_result
        end
        
        # At this point, we need to pull the RID value back out and set it
        # because it is needed later. This is needed even if the group was
        # found and not created because it had not been loaded yet. Later
        # calls like create_user() look for the RID of the primary_group.
        entry = @ldap.search(:base => group.distinguished_name,
                             :filter => group_filter,
                             :scope => Net::LDAP::SearchScope_BaseObject).pop
        group.set_rid sid2rid_int(entry.objectSid.pop)
        # Note: unlike a user, the group cannot be considered loaded at this
        # point because we have not handled any group memberships that might
        # have been set. Users at this poing in the create_user() method
        # can be considered loaded. Just noting this for my own reference.
      end
    end
    
    # Update a Group or UNIXGroup in Active Directory. This method automatically
    # determines which attributes to update. The Group or UNIXGroup object must
    # exist in Active Directory or this method does nothing. This is checked, so
    # it is safe to pass any Group or UNIXGroup object to this method.
    #
    # === Parameter Types
    #
    # * group [Group or UNIXGroup]
    def update_group(group)
      if group.modified?
        RADUM::logger.log("[AD #{self.root}]" +
                          " update_group(<#{group.name}>)", LOG_DEBUG)
        group_filter = Net::LDAP::Filter.eq("objectclass", "group")
        entry = @ldap.search(:base => group.distinguished_name,
                             :filter => group_filter,
                             :scope => Net::LDAP::SearchScope_BaseObject).pop
        attr = group_ldap_entry_attr(entry)
        ops = []
        RADUM::logger.log("\tKey: AD Value =? Object Value", LOG_DEBUG)
        
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
          RADUM::logger.log("\t#{key}: #{ad_value} =? #{obj_value}", LOG_DEBUG)
          
          # Some attributes are integers and some are Strings, but they are
          # always Strings coming out of Active Directory. This is a safe
          # step to ensure a correct comparision.
          #
          # Note in this case I know these are always Strings, but I am doing
          # this anyway just in case they aren't someday.
          if ad_value.to_s != obj_value.to_s
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
            # The _membership versions find removed memberships for groups or
            # users who have not actually been removed from the AD object. This
            # reflects simple group and user membership changes, not removing
            # a user or group.
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
              
              # There is a special case here with the last condition. If the
              # user is a UNIX member of the group and the group is the primary
              # Windows group, meaning we've removed their Windows membership
              # above (because it is implicit), we don't want to blow away the
              # UNIX membership too.
              if user && user.instance_of?(UNIXUser) &&
                 group.instance_of?(UNIXGroup) && group != user.primary_group
                # There is a chance the user was never a UNIX member of this
                # UNIXGroup. This happens if the UNIX main group is changed
                # and then the user is removed from the group as well. We
                # should really also search the memberUid attribute, but
                # really... it should always match up with msSFU30PosixMember.
                begin
                  found = entry.msSFU30PosixMember.find do |member|
                    user.distinguished_name.downcase == member.downcase
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
        rescue NoMethodError
        end
        
        # Now add any users or groups that are not already in the members
        # attribute array. We don't want to add the same thing twice because
        # this actually seems to duplicate the entries.
        (group.users + group.groups).each do |item|
          # As in the above begin block, the member attribute might not exist.
          # We have to take that into account.
          found = false
          
          begin
            found = entry.member.find do |member|
              item.distinguished_name.downcase == member.downcase
            end
          rescue NoMethodError
          end
          
          # There is an order of operations issue here. This method is called
          # before update_user() is called. If this group was the previous
          # user's primary Windows group (meaning we changed it), then this
          # code would try and add the user as a member of that group - as it
          # should. However, since we've not actually updated the user yet,
          # they are still a member of this group by way of their user current
          # account primaryGroupID attribute. When that attribute is updated
          # in the update_user() method, the group membership we are trying
          # to do here will be done implicitly. Trying to add the user as a
          # member here will not cause the sync() method to die, but it will
          # generate an LDAP error return message. We should avoid that.
          # The solution is to check if the object represented by the member
          # variable (which is a distinguished name) is:
          #
          # 1. A user account.
          # 2. A user account that has this group as its primaryGroupID still.
          #
          # If those two cases are true, we won't add the user as a member here
          # to avoid an LDAP error return message. Instead, the membership will
          # be implicitly dealt with when update_user() updates the user account
          # attributes. If this is not the case, we do add them as a member.
          if item.instance_of?(User) || item.instance_of?(UNIXUser)
            user_filter = Net::LDAP::Filter.eq("objectclass", "user")
            obj = @ldap.search(:base => item.distinguished_name,
                              :filter => user_filter,
                              :scope => Net::LDAP::SearchScope_BaseObject).pop
            curr_primary_group_id = obj.primaryGroupID.pop.to_i
          
            unless found || curr_primary_group_id == group.rid
              ops.push [:add, :member, item.distinguished_name]
            end
          else
            # This is a Group or UNIXGroup member, which can just be added if
            # not already there.
            ops.push [:add, :member, item.distinguished_name] unless found
          end
          
          # UNIX main group memberships are handled in update_user() when there
          # are changes if necessary.
          if item.instance_of?(UNIXUser) && group.instance_of?(UNIXGroup) &&
             group != item.unix_main_group
            # As with the member attribute, the msSFU30PosixMember attribute
            # might not exist yet either.
            found = false
            
            begin
              # We should really also search the memberUid attribute, but
              # really... it should always match up with msSFU30PosixMember.
              found = entry.msSFU30PosixMember.find do |member|
                item.distinguished_name.downcase == member.downcase
              end
            rescue NoMethodError
            end
            
            unless found
              ops.push [:add, :memberUid, item.username]
              ops.push [:add, :msSFU30PosixMember, item.distinguished_name]
            end
          end
        end
        
        unless ops.empty?
          RADUM::logger.log("\n" + ops.to_yaml + "\n\n", LOG_DEBUG)
          @ldap.modify :dn => group.distinguished_name, :operations => ops
          check_ldap_result
          # At this point the group is the equivalent of a loaded group. Calling
          # this flags that fact as well as setting the hidden modified
          # attribute to false since we are up to date now.
          group.set_loaded
        else
          # The group did not need to be updated, so it can also be considered
          # loaded.
          group.set_loaded
          RADUM::logger.log("\tNo need to update group <#{group.name}>.",
                            LOG_DEBUG)
        end
      end
    end
    
    # Delete a User or UNIXUser from Active Directory.
    #
    # === Parameter Types
    #
    # * user [User or UNIXUser]
    def delete_user(user)
      RADUM::logger.log("[AD #{self.root}]" +
                        " delete_user(<#{user.username}>)", LOG_DEBUG)
      @ldap.delete :dn => user.distinguished_name
      check_ldap_result
      RADUM::logger.log("\tDestroying user <#{user.username}>.", LOG_DEBUG)
      user.container.destroy_user user
    end
    
    # Create a User or UNIXUser in Active Directory. The User or UNIXUser
    # must have its loaded attribute set to false, which indicates it was
    # manually created. This method checks that, so it is not necessary to
    # worry about checking first. This method also makes sure the user is not
    # already in Active Directory, in case someone created a user that would
    # match one that already exists. Therefore, any User or UNIXUser can be
    # passed into this method.
    #
    # === Parameter Types
    #
    # * user [User or UNIXUser]
    def create_user(user)
      unless user.loaded?
        user_filter = Net::LDAP::Filter.eq("objectclass", "user")
        # The return value will be false explicitly if the search fails,
        # otherwise it will be an array of entries. Therefore it is important
        # to check for false explicitly for a failure. A failure indicates
        # that the user needs to be created.
        found = @ldap.search(:base => user.distinguished_name,
                             :filter => user_filter,
                             :scope => Net::LDAP::SearchScope_BaseObject,
                             :return_result => false)
        
        # The user should not already exist of course. This is to make sure
        # it is not already there.
        if found == false
          RADUM::logger.log("[AD #{self.root}]" +
                            " create_user(<#{user.username}>)", LOG_DEBUG)
          # We need the RID of the user's primary Windows group, and at this
          # point the create_group() method has grabbed the RID for any group
          # that was not loaded. Only groups in the RADUM environment can be
          # specified as the primary group, so this should always give the
          # primary group RID.
          rid = user.primary_group.rid
          
          # We want to be sure though! The RID stuff is here so that we don't
          # even create a user if there is a primary Windows group RID issue.
          if rid.nil?
            RADUM::logger.log("SYNC ERROR: RID of " +
                              " <#{user.primary_group.name}> was nil.",
                              LOG_NORMAL)
            return
          end
          
          # Note that all the attributes need to be strings in this hash.
          attr = {
            # All users are of the objectclasses "top", "person",
            # "orgainizationalPerson", and "user".
            :objectclass => ["top", "person", "organizationalPerson", "user"],
            :sAMAccountName => user.username,
            :userAccountControl => (UF_NORMAL_ACCOUNT + UF_PASSWD_NOTREQD +
                                    UF_ACCOUNTDISABLE).to_s
          }
          
          description = ""
          
          # These are optional attributes.
          unless user.first_name.nil?
            attr.merge!({ :givenName => user.first_name })
            description += "#{user.first_name}"
          end
          
          unless user.initials.nil?
            attr.merge!({ :initials => user.initials })
            description += " #{user.initials}."
          end
          
          unless user.middle_name.nil?
            attr.merge!({ :middleName => user.middle_name })
          end
          
          unless user.surname.nil?
            attr.merge!({ :sn => user.surname })
            description += " #{user.surname}"
          end
          
          # We should set these to something in case they were not set.
          if description == ""
            description = user.username
          end
          
          realm = user.username + "@#{@domain}"
          
          attr.merge!({
            :displayName => description,
            :description => description,
            :userPrincipalName => realm
          })
          
          unless user.script_path.nil?
            attr.merge!({ :scriptPath => user.script_path })
          end
          
          unless user.profile_path.nil?
            attr.merge!({ :profilePath => user.profile_path })
          end
          
          if user.local_drive && user.local_path
            attr.merge!({
              :homeDrive => user.local_drive,
              :homeDirectory => user.local_path
            })
          elsif user.local_path
            attr.merge!({ :homeDirectory => user.local_path })
          end
          
          attr.merge!({
            :gecos => user.gecos,
            :gidNumber => user.unix_main_group.gid.to_s,
            :loginShell => user.shell,
            :msSFU30Name => user.username,
            :msSFU30NisDomain => user.nis_domain,
            :uidNumber => user.uid.to_s,
            :unixHomeDirectory => user.home_directory,
            :unixUserPassword => user.unix_password
          }) if user.instance_of?(UNIXUser)
          
          # The shadow file attributes are all optional, so we need to check
          # each one. The other UNIX attributes above are set to something
          # by default.
          if user.instance_of?(UNIXUser)
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
          
          RADUM::logger.log("\n" + attr.to_yaml + "\n\n", LOG_DEBUG)
          @ldap.add :dn => user.distinguished_name, :attributes => attr
          check_ldap_result
          
          # Modify the attributes for the user password and userAccountControl
          # value to enable the account.
          user_status = UF_NORMAL_ACCOUNT
          user_status += UF_ACCOUNTDISABLE if user.disabled?
          
          if user.password.nil?
            user.password = random_password
            RADUM::logger.log("\tGenerated password #{user.password} for" +
                              " <#{user.username}>.", LOG_DEBUG)
          end
          
          ops = [
            [:replace, :unicodePwd, str2utf16le(user.password)],
            [:replace, :userAccountControl, user_status.to_s]
          ]
          
          RADUM::logger.log("\n" + ops.to_yaml + "\n\n", LOG_DEBUG)
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
            
            RADUM::logger.log("\n" + ops.to_yaml + "\n\n", LOG_DEBUG)
            @ldap.modify :dn => user.distinguished_name, :operations => ops
            check_ldap_result
          end
          
          # The user already has the primary Windows group as Domain Users
          # based on the default actions above. If the user has a different
          # primary Windows group, it is necessary to add the user to that
          # group first (as a member in the member attribute for the group)
          # before attempting to set their primaryGroupID attribute or Active
          # Directory will refuse to do it. Note that there is no guarentee
          # that AD#load() has been called yet, so the Domain Users group
          # might not even be in the RADUM system. The safest way to check
          # if the user's primary Windows group is Domain Users is as done
          # below.
          unless user.primary_group.name == "Domain Users"
            ops = [
              [:add, :member, user.distinguished_name]
            ]
            
            RADUM::logger.log("\n" + ops.to_yaml + "\n\n", LOG_DEBUG)
            @ldap.modify :dn => user.primary_group.distinguished_name,
                         :operations => ops
            check_ldap_result
            
            ops = [
              [:replace, :primaryGroupID, rid.to_s]
            ]
            
            RADUM::logger.log("\n" + ops.to_yaml + "\n\n", LOG_DEBUG)
            @ldap.modify :dn => user.distinguished_name, :operations => ops
            check_ldap_result
            # The user has now been made a regular member of the Domain Users
            # Windows group. This has been handled in Active Directory for us,
            # but now we want to reflect that in the Domain Users Group object
            # here. There is a problem however. It is possible that the
            # Domain Users group has not been loaded into the RADUM environment
            # yet. Therefore, we check first before trying.
            domain_users = find_group_by_name("Domain Users")
            domain_users.add_user user if domain_users
          end
          
          # At this point, we need to pull the RID value back out and set it
          # because it is needed later. Actually, it isn't for users, but
          # I am pretending it is just as important because I am tracking
          # RIDs anyway (they are in a flat namespace).
          entry = @ldap.search(:base => user.distinguished_name,
                              :filter => user_filter,
                              :scope => Net::LDAP::SearchScope_BaseObject).pop
          user.set_rid sid2rid_int(entry.objectSid.pop)
          # At this point the user is the equivalent as a loaded user.
          # Calling this flags that fact as well as setting the hidden
          # modified attribute to false since we are up to date now. Note
          # that the groups attribute is still not 100% accurate. It will
          # be dealt with later when groups are dealt with.
          user.set_loaded
        end
      end
    end
    
    # Update a User or UNIXUser in Active Directory. This method automatically
    # determines which attributes to update. The User or UNIXUser object must
    # exist in Active Directory or this method does nothing. This is checked, so
    # it is safe to pass any User or UNIXUser object to this method.
    #
    # === Parameter Types
    #
    # * user [User or UNIXUser]
    def update_user(user)
      if user.modified?
        RADUM::logger.log("[AD #{self.root}]" +
                          " update_user(<#{user.username}>)", LOG_DEBUG)
        user_filter = Net::LDAP::Filter.eq("objectclass", "user")
        entry = @ldap.search(:base => user.distinguished_name,
                             :filter => user_filter,
                             :scope => Net::LDAP::SearchScope_BaseObject).pop
        attr = user_ldap_entry_attr(entry)
        ops = []
        # This for the UNIX group membership corner case below. Note that 0
        # is the case where the GID has been removed (UNIXUser converted to
        # a User). No one should have a GID of 0, so this is just to make the
        # check to proceed easier.
        old_gid = 0
        RADUM::logger.log("\tKey: AD Value =? Object Value", LOG_DEBUG)
        
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
          RADUM::logger.log("\t#{key}: #{ad_value} =? #{obj_value}", LOG_DEBUG)
          
          # Some attributes are integers and some are Strings, but they are
          # always Strings coming out of Active Directory. This is a safe
          # step to ensure a correct comparision.
          #
          # Note that in this case there is a comparision of the primary_group
          # value, which is represented as a Group/UNIXGroup object, but it
          # has a to_s() method that will work fine here. So yes, what I said
          # at first is not strictly true, but by "magic" this all works fine.
          # I mean, have you read this code? :-)
          if ad_value.to_s != obj_value.to_s
            case key
            when :disabled?
              user_status = UF_NORMAL_ACCOUNT
              user_status += UF_ACCOUNTDISABLE if obj_value
              ops.push [:replace, :userAccountControl, user_status.to_s]
            when :first_name
              ops.push [:replace, :givenName, obj_value]
            when :initials
              ops.push [:replace, :initials, obj_value]
            when :middle_name
              ops.push [:replace, :middleName, obj_value]
            when :surname
              ops.push [:replace, :sn, obj_value]
            when :script_path
              ops.push [:replace, :scriptPath, obj_value]
            when :profile_path
              ops.push [:replace, :profilePath, obj_value]
            when :local_path
              ops.push [:replace, :homeDirectory, obj_value]
            when :local_drive
              ops.push [:replace, :homeDrive, obj_value]
            when :primary_group
              @ldap.modify :dn => user.primary_group.distinguished_name,
                           :operations => [[:add, :member,
                                            user.distinguished_name]]
              check_ldap_result
              ops.push [:replace, :primaryGroupID, user.primary_group.rid.to_s]
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
              old_gid = ad_value.to_i
              ops.push [:replace, :gidNumber, obj_value.to_s]
            when :uid
              ops.push [:replace, :uidNumber, obj_value.to_s]
            when :must_change_password?
              if obj_value
                ops.push [:replace, :pwdLastSet, 0.to_s]
              else
                ops.push [:replace, :pwdLastSet, -1.to_s]
              end
            end
          end
        end
        
        # Update the LDAP description and displayName attributes. This only
        # updates them if they are different than what is currently there.
        description = ""
        
        unless user.first_name.nil?
          description = "#{user.first_name}"
        end
        
        unless user.initials.nil?
          description += " #{user.initials}."
        end
        
        unless user.surname.nil?
          description += " #{user.surname}"
        end
        
        curr_description = curr_display_name = nil
        
        begin
          curr_description = entry.description.pop
        rescue NoMethodError
        end
        
        begin
          curr_display_name = entry.displayName.pop
        rescue NoMethodError
        end
        
        if description != curr_description
          ops.push [:replace, :description, description]
        end
        
        if description != curr_display_name
          ops.push [:replace, :displayName, description]
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
        
        # This is a corner case with the UNIX main group. Due to the
        # complications in implicit UNIX group membership, primary Windows
        # groups having users as implicit members, etc. we just make sure
        # the user is made a UNIX member of the previous UNIX main group
        # when it was changed just in case they are not already a member.
        #
        # Note that when converting a UNIXUser to a User, there will be a
        # gid change, but the gid will be "".to_i (0). In that case, we don't
        # want to proceed with this logic. This isn't C, so "if 0" is true.
        # The old_gid variable is initialized to 0 too in order to make this
        # check easier. None should have a GID of 0.
        unless old_gid == 0
          group_ops = []
          group_filter = Net::LDAP::Filter.eq("objectclass", "group")
          group = find_group_by_gid old_gid
          entry = @ldap.search(:base => group.distinguished_name,
                               :filter => group_filter,
                               :scope => Net::LDAP::SearchScope_BaseObject).pop
          # Double check to make sure they are not already members. Since this
          # logic is difficult to deal with, the algorithm is simply to make
          # sure the UNIXUser is a member of their previous UNIX main group
          # if that has not been done by the update_group() method.
          found = false
          
          begin
            found = entry.msSFU30PosixMember.find do |member|
              user.distinguished_name.downcase == member.downcase
            end
          rescue NoMethodError
          end
          
          unless found
            group_ops.push [:add, :memberUid, user.username]
            group_ops.push [:add, :msSFU30PosixMember, user.distinguished_name]
            RADUM::logger.log("\nSpecial case 1: updating old UNIX main group" +
                              " UNIX membership for group <#{group.name}>.",
                              LOG_DEBUG)
            RADUM::logger.log("\n" + group_ops.to_yaml, LOG_DEBUG)
            @ldap.modify :dn => group.distinguished_name,
                         :operations => group_ops
            check_ldap_result
            RADUM::logger.log("\nSpecial case 1: end.\n\n", LOG_DEBUG)
          end
          
          # In this case, we also have to make sure the user is removed
          # from the new UNIX main group with respect to UNIX group membership.
          # This is because there is also a case where the UNIX main group is
          # being set to the primary Windows group, and thus would not cause
          # an update because the Windows group membership is implicit.
          group_ops = []
          group = user.unix_main_group
          entry = @ldap.search(:base => group.distinguished_name,
                               :filter => group_filter,
                               :scope => Net::LDAP::SearchScope_BaseObject).pop
          found = false
          
          begin
            found = entry.msSFU30PosixMember.find do |member|
              user.distinguished_name.downcase == member.downcase
            end
          rescue NoMethodError
          end
          
          if found
            group_ops.push [:delete, :memberUid, user.username]
            group_ops.push [:delete, :msSFU30PosixMember,
                            user.distinguished_name]
            RADUM::logger.log("\nSpecial case 2: removing UNIX main group" +
                              " UNIX membership for group <#{group.name}>.",
                              LOG_DEBUG)
            RADUM::logger.log("\n" + group_ops.to_yaml, LOG_DEBUG)
            @ldap.modify :dn => group.distinguished_name,
                         :operations => group_ops
            check_ldap_result
            RADUM::logger.log("\nSpecial case 2: end.\n\n", LOG_DEBUG)
          end
        end
        
        unless ops.empty?
          RADUM::logger.log("\n" + ops.to_yaml + "\n\n", LOG_DEBUG)
          @ldap.modify :dn => user.distinguished_name, :operations => ops
          check_ldap_result
          # At this point the user is the equivalent as a loaded user. Calling
          # this flags that fact as well as setting the hidden modified
          # attribute to false since we are up to date now.
          user.set_loaded
        else
          # The user did not need to be updated, so it can also be considered
          # loaded.
          user.set_loaded
          RADUM::logger.log("\tNo need to update user <#{user.username}>.",
                            LOG_DEBUG)
        end
      end
    end
  end
end
