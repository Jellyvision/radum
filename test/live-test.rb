#!/usr/bin/ruby -I ../lib

require 'test/unit'
require 'radum'

# This tests the User class.
class TC_Live < Test::Unit::TestCase
  def setup
    if ENV['LIVE_ROOT']
      @root = ENV['LIVE_ROOT']
    else
      usage
      raise "LIVE_ROOT environment variable not set."
    end
    
    if ENV['LIVE_USER']
      @user = ENV['LIVE_USER']
    else
      usage
      raise "LIVE_USER environment variable not set."
    end
    
    if ENV['LIVE_PASSWORD']
      @password = ENV['LIVE_PASSWORD']
    else
      usage
      raise "LIVE_PASSWORD environment variable not set."
    end
    
    if ENV['LIVE_SERVER']
      @server = ENV['LIVE_SERVER']
    else
      usage
      raise "LIVE_SERVER environment variable not set."
    end
    
    RADUM::logger.default_level = RADUM::LOG_DEBUG
    RADUM::logger.output_file "live-test.txt"
    RADUM::logger.log("\nInitializing...\n\n", RADUM::LOG_DEBUG)
    # The first AD object to create objects and modify them for testing. This
    # is just used for creating new objects, so there is no need to ever call
    # ad.load later - just call ad.sync whenever something new is added. The
    # new_ad method should be used to get a new AD object to make sure the
    # objects currently have the expected values in Active Directory.
    @ad = RADUM::AD.new :root => @root, :user => @user, :password => @password,
                        :server => @server
    @cn = RADUM::Container.new :name => "ou=Test-" + $$.to_s, :directory => @ad
    @ad.sync
    # Call ad.load once to get the users and groups in the Users container.
    # we're interested in the Domain Users group specifically.
    @ad.load
    @domain_users = @ad.find_group_by_name("Domain Users")
  end
  
  # Print out usage information regarding the variables that need to be set
  # to run live testing.
  def usage
    puts "\nLive testing requires the following environment variables:\n\n"
    puts "LIVE_ROOT\t-- The root of the AD (dc=example,dc=com)."
    puts "LIVE_USER\t-- The user to connect with (cn=Administrator,cn=Users)."
    puts "LIVE_PASSWORD\t-- The password for the user (use single quotes)."
    puts "LIVE_SERVER\t-- The server to connect to.\n\n"
  end
  
  # Get a new AD object to test the current values of modified objects from the
  # first AD object. To ensure we are always looking at current values, a new
  # AD object with the testing container is returned by this call. The AD
  # object is fully loaded.
  def new_ad
    ad_new = RADUM::AD.new :root => @root, :user => @user,
                           :password => @password, :server => @server
    RADUM::Container.new :name => "ou=Test-" + $$.to_s, :directory => ad_new
    ad_new.load
    ad_new
  end
  
  # This will return true if the user is not a UNIX member of the group, false
  # otherwise.
  def ldap_not_unix_group_member?(user, group)
    group_filter = Net::LDAP::Filter.eq("objectclass", "group")
    entry = @ad.ldap.search(:base => group.distinguished_name,
                            :filter => group_filter,
                            :scope => Net::LDAP::SearchScope_BaseObject).pop
    found = false
    
    begin
      found = entry.msSFU30PosixMember.find do |member|
        user.distinguished_name.downcase == member.downcase
      end
    rescue NoMethodError
    end
    
    !found
  end
  
  # This will return true if the user is a UNIX member of the group, false
  # otherwise.
  def ldap_unix_group_member?(user, group)
    group_filter = Net::LDAP::Filter.eq("objectclass", "group")
    entry = @ad.ldap.search(:base => group.distinguished_name,
                            :filter => group_filter,
                            :scope => Net::LDAP::SearchScope_BaseObject).pop
    found = false
    
    begin
      found = entry.msSFU30PosixMember.find do |member|
        user.distinguished_name.downcase == member.downcase
      end
    rescue NoMethodError
    end
    
    # The user object is the value of found if found, but we want a boolean
    # here. This is the easiest way.
    found != false
  end
  
  # This will return true if the group has no UNIX attributes defined, false
  # otherwise
  def ldap_no_group_unix_attributes?(group)
    group_filter = Net::LDAP::Filter.eq("objectclass", "group")
    entry = @ad.ldap.search(:base => group.distinguished_name,
                            :filter => group_filter,
                            :scope => Net::LDAP::SearchScope_BaseObject).pop
    
    begin
      entry.gidNumber.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.msSFU30NisDomain.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.unixUserPassword.pop
      return false
    rescue NoMethodError
    end
    
    return true
  end
  
  # This will return true if the user has no UNIX attributes defined, false
  # otherwise.
  def ldap_no_user_unix_attributes?(user)
    user_filter = Net::LDAP::Filter.eq("objectclass", "user")
    entry = @ad.ldap.search(:base => user.distinguished_name,
                            :filter => user_filter,
                            :scope => Net::LDAP::SearchScope_BaseObject).pop
    
    begin
      entry.uidNumber.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.gidNumber.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.msSFU30NisDomain.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.gecos.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.unixUserPassword.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowExpire.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowFlag.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowInactive.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowLastChange.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowMax.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowMin.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.shadowWarning.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.loginShell.pop
      return false
    rescue NoMethodError
    end
    
    begin
      entry.unixHomeDirectory.pop
      return false
    rescue NoMethodError
    end
    
    return true
  end
  
  def test_user_attributes_groups
    RADUM::logger.log("\ntest_user_attributes_groups()", RADUM::LOG_DEBUG)
    RADUM::logger.log("-----------------------------", RADUM::LOG_DEBUG)
    u = RADUM::User.new :username => "win-user-" + $$.to_s, :container => @cn,
                        :primary_group => @domain_users
    
    # Test setting all User attributes.
    u.first_name = "First Name"
    u.initials = "M"
    u.middle_name = "Middle Name"
    u.surname = "Surname"
    u.script_path = "\\\\script\\path"
    u.profile_path = "\\\\profile\\path"
    u.local_path = "D:\\Local Path"
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.first_name == "First Name", "first_name should be 'First Name'")
    assert(u2.initials == "M", "initials should be 'M'")
    assert(u2.middle_name == "Middle Name",
           "middle_name should be 'Middle Name'")
    assert(u2.script_path == "\\\\script\\path",
           "script_path should be '\\\\script\\path'")
    assert(u2.profile_path == "\\\\profile\\path",
           "profile_path should be '\\\\profile\\path'")
    assert(u2.local_path == "D:\\Local Path",
           "local_path should be 'D:\\Local Path'")
    
    # Test modifying all set User attributes.
    u.first_name = "New First Name"
    u.initials = "N"
    u.middle_name = "New Middle Name"
    u.surname = "New Surname"
    u.script_path = "\\\\new\\script\\path"
    u.profile_path = "\\\\new\\profile\\path"
    u.local_path = "D:\\New Local Path"
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.first_name == "New First Name",
           "first_name should be 'New First Name'")
    assert(u2.initials == "N", "initials should be 'N'")
    assert(u2.middle_name == "New Middle Name",
           "middle_name should be 'New Middle Name'")
    assert(u2.script_path == "\\\\new\\script\\path",
           "script_path should be '\\\\new\\script\\path'")
    assert(u2.profile_path == "\\\\new\\profile\\path",
           "profile_path should be '\\\\new\\profile\\path'")
    assert(u2.local_path == "D:\\New Local Path",
           "local_path should be 'D:\\New Local Path'")
    
    # Test User#connect_path_to settings are correct.
    u.connect_drive_to "Z:", "\\\\server\\share"
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.local_drive == "Z:", "local_drive should be 'Z:'")
    assert(u2.local_path == "\\\\server\\share",
           "local_path should be '\\\\server\\share'")
    u.local_path = "D:\\A Path"
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.local_drive == nil, "local_drive should be nil")
    assert(u2.local_path == "D:\\A Path", "local_path should be 'D:\\A Path'")
    
    # Test must change password logic. First check that it is really false to
    # begin with when we've not employed this logic whatsoever. Note we can't
    # really test if setting a password will work here, but I know it does from
    # testing by hand :-)
    assert(u2.must_change_password? == false,
           "must_change_password? should be false")
    u.force_change_password
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.must_change_password? == true,
           "must_change_password? should be true")
    u.unset_change_password
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.must_change_password? == false,
           "must_change_password? should be false")
    
    # Test enabled and disabled logic. First check that the user is really
    # enabled to begin with when we've not employed this logic whatsoever.
    assert(u2.disabled? == false, "disabled? should be false")
    u.disable
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.disabled? == true, "disabled? should be true")
    u.enable
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.disabled? == false, "disabled? should be false")
    
    # Test changing the primary Windows group.
    du = ad2.find_group_by_name("Domain Users")
    assert(u2.primary_group == du, "primary_group should be #{du}")
    g1 = RADUM::Group.new :name => "win-group-" + $$.to_s, :container => @cn
    u.primary_group = g1
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    pg = ad2.find_group_by_name("win-group-" + $$.to_s)
    old_pg = ad2.find_group_by_name("Domain Users")
    assert(u2.primary_group == pg, "primary_group should be #{pg}")
    assert(u2.member_of?(pg) == true, "user should be member of #{pg}")
    assert(u2.member_of?(old_pg) == true, "user should be member of #{old_pg}")
    u.primary_group = @domain_users
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    pg = ad2.find_group_by_name("Domain Users")
    old_pg = ad2.find_group_by_name("win-group-" + $$.to_s)
    assert(u2.primary_group == pg, "primary_group should be #{pg}")
    assert(u2.member_of?(pg) == true, "user should be member of #{pg}")
    assert(u2.member_of?(old_pg) == true, "user should be member of #{old_pg}")
    
    # Test group membership additions and removals.
    g2 = RADUM::Group.new :name => "win-group2-" + $$.to_s, :container => @cn
    g3 = RADUM::Group.new :name => "win-group3-" + $$.to_s, :container => @cn
    u.add_group g2
    g3.add_user u
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("win-group2-" + $$.to_s)) ==
           true, "user should be a member of new group 2")
    assert(u2.member_of?(ad2.find_group_by_name("win-group3-" + $$.to_s)) ==
           true, "user should be a member of new group 3")
    u.remove_group g2
    g3.remove_user u
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("win-group2-" + $$.to_s)) ==
           false, "user should not be a member of new group 2")
    assert(u2.member_of?(ad2.find_group_by_name("win-group3-" + $$.to_s)) ==
           false, "user should not be a member of new group 3")
    
    # Test removing then adding back the user and groups created (they should
    # not be added back).
    @cn.remove_user u
    @cn.remove_group g1
    @cn.remove_group g2
    @cn.remove_group g3
    @ad.sync
    
    ad2 = new_ad
    assert(ad2.find_user_by_username("win-user-" + $$.to_s) == nil,
           "user should not have been found after removal")
    assert(ad2.find_group_by_name("win-group-" + $$.to_s) == nil,
           "group 1 should not have been found after removal")
    assert(ad2.find_group_by_name("win-group2-" + $$.to_s) == nil,
           "group 2 should not have been found after removal")
    assert(ad2.find_group_by_name("win-group3-" + $$.to_s) == nil,
           "group 3 should not have been found after removal")
    @cn.add_user u
    @cn.add_group g1
    @cn.add_group g2
    @cn.add_group g3
    @ad.sync
    
    ad2 = new_ad
    assert(ad2.find_user_by_username("win-user-" + $$.to_s) == nil,
           "user should not have been found after adding back when removed")
    assert(ad2.find_group_by_name("win-group-" + $$.to_s) == nil,
           "group 1 should not have been found after adding back when removed")
    assert(ad2.find_group_by_name("win-group2-" + $$.to_s) == nil,
           "group 2 should not have been found after adding back when removed")
    assert(ad2.find_group_by_name("win-group2-" + $$.to_s) == nil,
           "group 3 should not have been found after adding back when removed")
    
    # Remove the Container now that we are done with it.
    @ad.remove_container @cn
    @ad.sync
    
    # Try adding the Container back. This should not work. This is only tested
    # once, and I wrote this test method first, so here we go...
    @ad.add_container @cn
    assert(@ad.find_container(@cn.name) == nil,
           "container should not have been added when removed")
    @ad.sync
  end
  
  def test_unix_user_attributes_unix_groups
    RADUM::logger.log("\ntest_unix_user_attributes_unix_groups()",
                      RADUM::LOG_DEBUG)
    RADUM::logger.log("---------------------------------------",
                      RADUM::LOG_DEBUG)
    g = RADUM::UNIXGroup.new :name => "unix-group-" + $$.to_s,
                             :container => @cn, :gid => @ad.load_next_gid,
                             :nis_domain => "vmware"
    u = RADUM::UNIXUser.new :username => "unix-user-" + $$.to_s,
                            :container => @cn, :primary_group => @domain_users,
                            :uid => @ad.load_next_uid,
                            :unix_main_group => g, :shell => "/bin/bash",
                            :home_directory => "/home/unix-user-" + $$.to_s,
                            :nis_domain => "foo"
    
    # Test setting all UNIXUser attributes.
    u.gecos = "GECOS"
    u.unix_password = "password"
    u.shadow_expire = 1
    u.shadow_flag = 2
    u.shadow_inactive = 3
    u.shadow_last_change = 4
    u.shadow_max = 5
    u.shadow_min = 6
    u.shadow_warning = 7
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.shell == "/bin/bash", "shell should be 'bash'")
    assert(u2.home_directory == "/home/unix-user-" + $$.to_s,
           "home_directory should be '/home/unix-user-#{$$.to_s}'")
    assert(u2.nis_domain == "foo", "nis_domain should be 'foo'")
    assert(u2.gecos == "GECOS", "gecos should be 'GECOS'")
    assert(u2.unix_password == "password", "password should be 'password'")
    assert(u2.shadow_expire == 1, "shadow_expire should be 1")
    assert(u2.shadow_flag == 2, "shadow_flag should be 2")
    assert(u2.shadow_inactive == 3, "shadow_inactive should be 3")
    assert(u2.shadow_last_change == 4, "shadow_last_change should be 4")
    assert(u2.shadow_max == 5, "shadow_max should be 5")
    assert(u2.shadow_min == 6, "shadow_min should be 6")
    assert(u2.shadow_warning == 7, "shadow_warning should be 7")
    
    # Test modifying all set User attributes. Here the shadow file attributes
    # are passed as String objects just to make sure that works.
    u.shell = "/bin/ksh" # You know I can't set that to /bin/tcsh... right?
    u.home_directory = "/home/foo"
    u.nis_domain = "vmware"
    u.gecos = "New GECOS"
    u.unix_password = "*"
    u.shadow_expire = "11"
    u.shadow_flag = "12"
    u.shadow_inactive = "13"
    u.shadow_last_change = "14"
    u.shadow_max = "15"
    u.shadow_min = "16"
    u.shadow_warning = "17"
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.shell == "/bin/ksh", "shell should be 'bash'")
    assert(u2.home_directory == "/home/foo",
           "home_directory should be '/home/foo'")
    assert(u2.nis_domain == "vmware", "nis_domain should be 'vmware'")
    assert(u2.gecos == "New GECOS", "gecos should be 'New GECOS'")
    assert(u2.unix_password == "*", "password should be '*'")
    assert(u2.shadow_expire == 11, "shadow_expire should be 11")
    assert(u2.shadow_flag == 12, "shadow_flag should be 12")
    assert(u2.shadow_inactive == 13, "shadow_inactive should be 13")
    assert(u2.shadow_last_change == 14, "shadow_last_change should be 14")
    assert(u2.shadow_max == 15, "shadow_max should be 15")
    assert(u2.shadow_min == 16, "shadow_min should be 16")
    assert(u2.shadow_warning == 17, "shadow_warning should be 17")
    
    # Test changing the UNIX main group.
    assert(u2.gid == g.gid, "GID is not set correctly")
    ug = ad2.find_group_by_name("unix-group-" + $$.to_s)
    assert(u2.unix_main_group == ug, "unix_main_group should be #{ug}")
    assert(u2.member_of?(ug) == true,
           "user should be a Windows member of unix_main_group")
    assert(ldap_not_unix_group_member?(u, g),
           "should not be a UNIX member of unix_main_group")
    g2 = RADUM::UNIXGroup.new :name => "unix-group2-" + $$.to_s,
                             :container => @cn, :gid => @ad.load_next_gid,
                             :nis_domain => "vmware"
    u.unix_main_group = g2
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.gid == g2.gid, "GID is not set correctly")
    ug = ad2.find_group_by_name("unix-group2-" + $$.to_s)
    assert(u2.unix_main_group == ug, "unix_main_group should be #{ug}")
    assert(u2.member_of?(ug) == true,
           "user should be a Windows member of unix_main_group")
    assert(ldap_not_unix_group_member?(u, g2),
           "user should not be a UNIX member of unix_main_group")
    assert(ldap_unix_group_member?(u, g),
           "user should be a UNIX member of old unix_main_group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of old unix_main_group")
    u.unix_main_group = g
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.gid == g.gid, "GID is not set correctly")
    ug = ad2.find_group_by_name("unix-group-" + $$.to_s)
    assert(u2.unix_main_group == ug, "unix_main_group should be #{ug}")
    assert(u2.member_of?(ug) == true,
           "user should be a Windows member of unix_main_group")
    assert(ldap_not_unix_group_member?(u, g),
           "user should not be a UNIX member of unix_main_group")
    # Because g2 was the previous UNIX main group and it was changed to g.
    ug2 = ad2.find_group_by_name("unix-group2-" + $$.to_s)
    assert(u2.member_of?(ug2) == true,
           "user should be a Windows member of unix group 2")
    assert(ldap_unix_group_member?(u, g2),
           "user should be a UNIX member of unix group 2")
    
    # Test UNIX group membership additions and removals.
    g3 = RADUM::UNIXGroup.new :name => "unix-group3-" + $$.to_s,
                              :container => @cn, :gid => @ad.load_next_gid,
                              :nis_domain => "vmware"
    
    # The user is still in group g2 because we switched their main group to
    # g when it was g2 previously.
    u.add_group g3
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of unix_main_group")
    assert(ldap_not_unix_group_member?(u, g),
           "user should not be a UNIX member of unix_main_group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group2-" + $$.to_s)) ==
           true, "user should be a Windows member of unix group 2")
    assert(ldap_unix_group_member?(u, g2),
           "user should be a UNIX member of unix group 2")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group3-" + $$.to_s)) ==
           true, "user should be a Windows member of unix group 3")
    assert(ldap_unix_group_member?(u, g3),
           "user should be a UNIX member of unix group 3")
    u.remove_group g2
    g3.remove_user u
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of unix_main_group")
    assert(ldap_not_unix_group_member?(u, g),
           "user should not be a UNIX member of unix_main_group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group2-" + $$.to_s)) ==
           false, "user should not be a Windows member of unix group 2")
    assert(ldap_not_unix_group_member?(u, g2),
           "user should not be a UNIX member of unix group 2")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group3-" + $$.to_s)) ==
           false, "user should not be a Windows member of unix group 3")
    assert(ldap_not_unix_group_member?(u, g3),
           "user should not be a UNIX member of unix group 3")
    
    # Now do the same group membership additions and removals when one of the
    # groups is set as the primary Windows group as well. The group g is the
    # UNIX main group as well as the primary Windows group after setting below:
    u.primary_group = g
    g3.add_user u
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of new primary group")
    assert(ldap_not_unix_group_member?(u, g),
           "user should not be a UNIX member of new primary group")
    assert(u2.primary_group == u2.unix_main_group,
           "user primary Windows group should be the same as UNIX main group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group3-" + $$.to_s)) ==
           true, "user should be a Windows member of new group 3")
    assert(ldap_unix_group_member?(u, g3),
           "user should be a UNIX member of unix group 3")
    assert(u2.member_of?(ad2.find_group_by_name("Domain Users")) == true,
           "user should keep Windows membership in old primary group")
    
    # Now switch the primary Windows group to g3 and remove membership in
    # g2.
    u.primary_group = g3
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of old primary Windows group")
    assert(ldap_not_unix_group_member?(u, g),
           "user should not be a UNIX member of UNIX main group")
    assert(u2.primary_group != u2.unix_main_group,
           "user primary Windows group should not be same as UNIX main group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group3-" + $$.to_s)) ==
           true, "user should be a Windows member of new primary Windows group")
    assert(ldap_unix_group_member?(u, g3),
           "user should be a UNIX member of new primary Windows group")
    assert(u2.member_of?(ad2.find_group_by_name("Domain Users")) == true,
           "user should be a Windows member of Domain Users")
    
    # Now we switch the UNIX main group to the current group and test.
    u.unix_main_group = g3
    # Just doing these steps to make sure they don't hose up the logic. The
    # end result should be the same as just doing the above step!
    u.primary_group = g
    u.unix_main_group = g
    u.unix_main_group = g3
    u.primary_group = g3
    @ad.sync
    
    ad2 = new_ad
    u2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    assert(u2.member_of?(ad2.find_group_by_name("unix-group3-" + $$.to_s)) ==
           true, "user should be a Windows member of primary group")
    assert(ldap_not_unix_group_member?(u, g3),
           "user should not be a UNIX member of primary group")
    assert(u2.primary_group == u2.unix_main_group,
           "user primary Windows group should be the same as UNIX main group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of old UNIX main group")
    assert(ldap_unix_group_member?(u, g),
           "user should be a UNIX member of old UNIX main group")
    assert(u2.member_of?(ad2.find_group_by_name("unix-group-" + $$.to_s)) ==
           true, "user should be a Windows member of old UNIX main group")
    assert(u2.member_of?(ad2.find_group_by_name("Domain Users")) == true,
           "user should be a Windows member of Domain Users")
    
    # Remove the Container now that we are done with it. We have to change
    # the test user account's primary Windows group first.
    u.primary_group = @domain_users
    @ad.remove_container @cn
    @ad.sync
  end
  
  def test_unix_windows_conversions
    RADUM::logger.log("\ntest_unix_windows_conversions()", RADUM::LOG_DEBUG)
    RADUM::logger.log("-------------------------------", RADUM::LOG_DEBUG)
    wu = RADUM::User.new :username => "win-user-" + $$.to_s, :container => @cn,
                         :primary_group => @domain_users
    wg = RADUM::Group.new :name => "win-group-" + $$.to_s, :container => @cn
    ug = RADUM::UNIXGroup.new :name => "unix-group-" + $$.to_s,
                              :container => @cn, :gid => @ad.load_next_gid,
                              :nis_domain => "vmware"
    uu = RADUM::UNIXUser.new :username => "unix-user-" + $$.to_s,
                             :container => @cn, :primary_group => @domain_users,
                             :uid => @ad.load_next_uid,
                             :unix_main_group => ug, :shell => "/bin/bash",
                             :home_directory => "/home/unix-user-" + $$.to_s,
                             :nis_domain => "vmware"
    
    # Set User attributes.
    wu.first_name = "First Name"
    wu.initials = "M"
    wu.middle_name = "Middle Name"
    wu.surname = "Last Name"
    wu.script_path = "\\\\script\\path"
    wu.profile_path = "\\\\profile\\path"
    wu.local_path = "D:\\Local Path"
    
    # Set UNIXUser attributes.
    uu.first_name = "First"
    uu.initials = "M"
    uu.middle_name = "Middle"
    uu.surname = "Surname"
    uu.script_path = "\\\\uu\\script\\path"
    uu.profile_path = "\\\\uu\\profile\\path"
    uu.connect_drive_to "Z", "\\\\uu\\local\\path"
    uu.gecos = "GECOS"
    uu.unix_password = "password"
    uu.shadow_expire = 1
    uu.shadow_flag = 2
    uu.shadow_inactive = 3
    uu.shadow_last_change = 4
    uu.shadow_max = 5
    uu.shadow_min = 6
    uu.shadow_warning = 7
    @ad.sync
    
    # Grab the RID values to make sure they do not actually change. This is
    # used later to make sure the objectSid value has not changed.
    wu_rid = wu.rid
    uu_rid = uu.rid
    
    # Convert the Windows user to a UNIX user. I left off the nis_domain. It
    # should end up being "vmware".
    wu_uid = @ad.load_next_uid
    @ad.user_to_unix_user :user => wu, :uid => wu_uid,
                          :unix_main_group => ug, :shell => "/bin/bash",
                          :home_directory => "/home/foo"
    # Convert the UNIX user to a Windows user, also add a new UNIX group for
    # further testing.
    ug_new = RADUM::UNIXGroup.new :name => "unix-group-new-" + $$.to_s,
                                  :container => @cn, :gid => @ad.load_next_gid,
                                  :nis_domain => "vmware"
    uu.add_group ug_new
    @ad.unix_user_to_user :user => uu
    @ad.sync
    
    ad2 = new_ad
    wu2 = ad2.find_user_by_username("win-user-" + $$.to_s)
    ug2 = ad2.find_group_by_name("unix-group-" + $$.to_s)
    ug_new2 = ad2.find_group_by_name("unix-group-new-" + $$.to_s)
    uu2 = ad2.find_user_by_username("unix-user-" + $$.to_s)
    
    # The users are now the opposite types.
    assert(wu2.instance_of?(RADUM::UNIXUser), "user should be a UNIXUser")
    assert(uu2.instance_of?(RADUM::User), "user should be a User")
    assert(ldap_no_user_unix_attributes?(uu2),
           "user should have no UNIX attributes")
    
    # Check to make sure the objectSid values have not changed. The RID values
    # should be the same.
    assert(wu_rid == wu2.rid, "user objectSid (RID) changed")
    assert(uu_rid == uu2.rid, "user objectSid (RID) changed")
    
    # Make sure none of the attributes set have been changed.
    assert(wu2.first_name == "First Name",
           "user first_name should be 'First Name'")
    assert(wu2.initials == "M", "user initials should be 'M'")
    assert(wu2.middle_name == "Middle Name",
           "user middle_name should be 'Middle Name'")
    assert(wu2.surname == "Last Name", "user surname should be 'Last Name'")
    assert(wu2.script_path == "\\\\script\\path",
           "user script_path should be '\\\\script\\path'")
    assert(wu2.profile_path == "\\\\profile\\path",
           "user profile_path should be '\\\\profile\\path'")
    assert(wu2.local_path == "D:\\Local Path",
           "user local_path shold be 'D:\\Local Path'")
    # Also check settings from conversion itself.
    assert(wu2.uid == wu_uid, "user uid should be #{wu_uid}")
    assert(wu2.gid == ug2.gid, "user gid should be #{ug2.gid}")
    assert(wu2.unix_main_group == ug2, "user unix_main_group should be #{ug2}")
    assert(wu2.shell == "/bin/bash", "user shell should be '/bin/bash'")
    assert(wu2.home_directory == "/home/foo",
           "user home_directory should be '/home/foo'")
    # This is the default value.
    assert(wu2.nis_domain == "radum", "user nis_domain should be 'radum'")
    
    # Now the converted UNIX user.
    assert(uu2.first_name == "First", "user first_name should be 'First'")
    assert(uu2.initials == "M", "user initials should be 'M'")
    assert(uu2.middle_name == "Middle", "user middle_name should be 'Middle'")
    assert(uu2.surname == "Surname", "user surname should be 'Surname'")
    assert(uu2.script_path == "\\\\uu\\script\\path",
           "user script_path should be '\\\\uu\\script\\path'")
    assert(uu2.profile_path == "\\\\uu\\profile\\path",
           "user profile_path should be '\\\\uu\\profile\\path'")
    assert(uu2.local_drive == "Z", "user local_drive should be 'Z'")
    assert(uu2.local_path == "\\\\uu\\local\\path",
           "user local_path should be '\\\\uu\\local\\path'")
    # Make sure the UNIXGoup Windows membership aspect was not changed but
    # the UNIXGroup UNIX membership was changed. This is the default for
    # UNIXUser to User conversions.
    assert(uu2.member_of?(ug2),
           "user should still be a Windows member of its old UNIX main group")
    assert(ldap_not_unix_group_member?(uu2, ug2),
           "user should only be a member from the Windows perspective")
    assert(uu2.member_of?(ug_new2),
           "user should still be a Windows member of its old UNIX group")
    assert(ldap_not_unix_group_member?(uu2, ug_new2),
           "user should only be a member from the Windows perspective")
    
    # We now repeat the same type of conversion, but in this case the
    # :remove_unix_groups flag is set so that the resulting Windows memberships
    # in any UNIX groups are also removed.
    nuu = RADUM::UNIXUser.new :username => "new-unix-user-" + $$.to_s,
                              :container => @cn,
                              :primary_group => @domain_users,
                              :uid => @ad.load_next_uid,
                              :unix_main_group => ug, :shell => "/bin/bash",
                              :home_directory => "/home/new-unix-user-" +
                                                 $$.to_s,
                              :nis_domain => "vmware"
    # Add a Windows group (non-UNIXGroup group - should not be removed).
    nuu.add_group wg
    # Add a UNIXGroup (should be removed).
    nuu.add_group ug_new
    @ad.sync
    
    # Convert to a Windows user with the :remove_unix_groups flag set to true.
    @ad.unix_user_to_user :user => nuu, :remove_unix_groups => true
    @ad.sync
    
    ad2 = new_ad
    wg2 = ad2.find_group_by_name("win-group-" + $$.to_s)
    ug2 = ad2.find_group_by_name("unix-group-" + $$.to_s)
    ug_new2 = ad2.find_group_by_name("unix-group-new-" + $$.to_s)
    nuu2 = ad2.find_user_by_username("new-unix-user-" + $$.to_s)
    # Make sure the Windows group memberships were not removed for non-UNIXGroup
    # objects, but UNIXGroup memberships were removed (from the Windows
    # perspective).
    assert(nuu2.member_of?(wg2),
           "user should be a member of previous Windows Group object")
    assert(nuu2.member_of?(ug2) == false,
           "user should not be a Windows member of previous UNIXGroup")
    assert(ldap_not_unix_group_member?(nuu2, ug2),
           "user should not be a member of pervious UNIXGroup wrt. UNIX attrs")
    assert(nuu2.member_of?(ug_new2) == false,
           "user should not be a Windows member of previous UNIXGroup")
    assert(ldap_not_unix_group_member?(nuu2, ug_new2),
           "user should not be a member of pervious UNIXGroup wrt. UNIX attrs")
    
    # Remove the Container now that we are done with it
    @ad.remove_container @cn
    @ad.sync
  end
  
  def test_group_attributes
    RADUM::logger.log("\ntest_group_attributes()", RADUM::LOG_DEBUG)
    RADUM::logger.log("-----------------------", RADUM::LOG_DEBUG)
    # Group memberships for Users have already been tested, so we'll test to
    # make sure a Group is a member of a Group correctly. None of the other
    # attributes (aside from mebers) can be modified after creation, so we'll
    # just make sure those are fine.
    group1 = RADUM::Group.new :name => "test1-" + $$.to_s, :container => @cn
    group2 = RADUM::Group.new :name => "test2-" + $$.to_s, :container => @cn
    group1.add_group group2
    @ad.sync
    
    # Check group membership in groups.
    ad2 = new_ad
    group1 = ad2.find_group_by_name("test1-" + $$.to_s)
    group2 = ad2.find_group_by_name("test2-" + $$.to_s)
    assert(group2.member_of?(group1) == true,
           "group2 should be a member of group1")
    assert(group1.member_of?(group2) == false,
           "group1 should not be a member of group2")
    
    # Test attributes.
    assert(group1.type == RADUM::GROUP_GLOBAL_SECURITY,
           "group should be of type RADUM::GROUP_GLOBAL_SECURITY")
    RADUM::Group.new :name => "dls-" + $$.to_s, :container => @cn,
                     :type => RADUM::GROUP_DOMAIN_LOCAL_SECURITY
    RADUM::Group.new :name => "dld-" + $$.to_s, :container => @cn,
                     :type => RADUM::GROUP_DOMAIN_LOCAL_DISTRIBUTION
    RADUM::Group.new :name => "gd-" + $$.to_s, :container => @cn,
                     :type => RADUM::GROUP_GLOBAL_DISTRIBUTION
    RADUM::Group.new :name => "us-" + $$.to_s, :container => @cn,
                     :type => RADUM::GROUP_UNIVERSAL_SECURITY
    RADUM::Group.new :name => "ud-" + $$.to_s, :container => @cn,
                     :type => RADUM::GROUP_UNIVERSAL_DISTRIBUTION
    @ad.sync
    
    ad2 = new_ad
    dls = ad2.find_group_by_name("dls-" + $$.to_s)
    dld = ad2.find_group_by_name("dld-" + $$.to_s)
    gd = ad2.find_group_by_name("gd-" + $$.to_s)
    us = ad2.find_group_by_name("us-" + $$.to_s)
    ud = ad2.find_group_by_name("ud-" + $$.to_s)
    assert(dls.type == RADUM::GROUP_DOMAIN_LOCAL_SECURITY,
           "group should be of type RADUM::GROUP_DOMAIN_LOCAL_SECURITY")
    assert(dld.type == RADUM::GROUP_DOMAIN_LOCAL_DISTRIBUTION,
           "group should be of type RADUM::GROUP_DOMAIN_LOCAL_DISTRIBUTION")
    assert(gd.type == RADUM::GROUP_GLOBAL_DISTRIBUTION,
           "group should be of type RADUM::GROUP_GLOBAL_DISTRIBUTION")
    assert(us.type == RADUM::GROUP_UNIVERSAL_SECURITY,
           "group should be of type RADUM::GROUP_UNIVERSAL_SECURITY")
    assert(ud.type == RADUM::GROUP_UNIVERSAL_DISTRIBUTION,
           "group should be of type RADUM::GROUP_UNIVERSAL_DISTRIBUTION")
    
    # Remove the Container now that we are done with it
    @ad.remove_container @cn
    @ad.sync
  end
  
  def foo_test_unix_group_attributes
    RADUM::logger.log("\ntest_unix_group_attributes()", RADUM::LOG_DEBUG)
    RADUM::logger.log("----------------------------", RADUM::LOG_DEBUG)
    # UNIXGroup memberships have already been tested, and Group mebershipds were
    # also tested, so we'll just test to make sure the UNIX attributes are
    # handled correctly.
    gid = @ad.load_next_gid
    ug = RADUM::UNIXGroup.new :name => "unix-group-" + $$.to_s,
                              :container => @cn, :gid => gid
    @ad.sync
    
    ad2 = new_ad
    ug2 = ad2.find_group_by_name("unix-group-" + $$.to_s)
    assert(ug2.gid == gid, "UNIXGroup gid is incorrect.")
    assert(ug2.nis_domain == "vmware", "UNIXGroup NIS domain is incorrect")
    # Check the one thing we can change (aside from members).
    ug.nis_domain = "vmware"
    @ad.sync
    
    ad2 = new_ad
    ug2 = ad2.find_group_by_name("unix-group-" + $$.to_s)
    assert(ug2.nis_domain == "vmware", "UNIXGroup NIS domain is incorrect")
    
    # Remove the Container now that we are done with it
    @ad.remove_container @cn
    @ad.sync
  end
end
