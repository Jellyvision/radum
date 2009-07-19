#!/usr/bin/ruby -I ../lib

require 'test/unit'
require '../lib/radum'

# This tests the User class.
class TC_Live < Test::Unit::TestCase
  def setup
    if ENV['LIVE_ROOT']
      @root = ENV['LIVE_ROOT']
    else
      raise "LIVE_ROOT environment variable not set."
    end
    
    if ENV['LIVE_USER']
      @user = ENV['LIVE_USER']
    else
      raise "LIVE_USER environment variable not set."
    end
    
    if ENV['LIVE_PASSWORD']
      @password = ENV['LIVE_PASSWORD']
    else
      raise "LIVE_PASSWORD environment variable not set."
    end
    
    if ENV['LIVE_SERVER']
      @server = ENV['LIVE_SERVER']
    else
      raise "LIVE_SERVER environment variable not set."
    end
    
    RADUM::logger.default_level = RADUM::LOG_DEBUG
    RADUM::logger.output_file "live-test.txt"
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
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
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
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
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
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    assert(u2.local_drive == "Z:", "local_drive should be 'Z:'")
    assert(u2.local_path == "\\\\server\\share",
           "local_path should be '\\\\server\\share'")
    u.local_path = "D:\\A Path"
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
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
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    assert(u2.must_change_password? == true,
           "must_change_password? should be true")
    u.unset_change_password
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    assert(u2.must_change_password? == false,
           "must_change_password? should be false")
    
    # Test enabled and disabled logic. First check that the user is really
    # enabled to begin with when we've not employed this logic whatsoever.
    assert(u2.disabled? == false, "disabled? should be false")
    u.disable
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    assert(u2.disabled? == true, "disabled? should be true")
    u.enable
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    assert(u2.disabled? == false, "disabled? should be false")
    
    # Test changing the primary Windows group.
    du = ad2.find_group_by_name("Domain Users")
    assert(u2.primary_group == du, "primary_group should be #{du}")
    g1 = RADUM::Group.new :name => "win-group-" + $$.to_s, :container => @cn
    u.primary_group = g1
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    du = ad2.find_group_by_name("Domain Users")
    pg = ad2.find_group_by_name("win-group-" + $$.to_s)
    assert(u2.primary_group == pg, "primary_group should be #{pg}")
    u.primary_group = @domain_users
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    du = ad2.find_group_by_name("Domain Users")
    assert(u2.primary_group == du, "primary_group should be #{du}")
    
    # Test group membership additions and removals.
    g2 = RADUM::Group.new :name => "win-group2-" + $$.to_s, :container => @cn
    g3 = RADUM::Group.new :name => "win-group3-" + $$.to_s, :container => @cn
    u.add_group g2
    g3.add_user u
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    assert(u2.member_of?(ad2.find_group_by_name("win-group2-" + $$.to_s)) ==
           true, "user should be a member of new group 2")
    assert(u2.member_of?(ad2.find_group_by_name("win-group3-" + $$.to_s)) ==
           true, "user should be a member of new group 3")
    u.remove_group g2
    g3.remove_user u
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
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
                            :nis_domain => "vmware"
    
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
    u2 = ad2.find_user_by_username "unix-user-" + $$.to_s
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
    u2 = ad2.find_user_by_username "unix-user-" + $$.to_s
    assert(u2.gecos == "New GECOS", "gecos should be 'New GECOS'")
    assert(u2.unix_password == "*", "password should be '*'")
    assert(u2.shadow_expire == 11, "shadow_expire should be 11")
    assert(u2.shadow_flag == 12, "shadow_flag should be 12")
    assert(u2.shadow_inactive == 13, "shadow_inactive should be 13")
    assert(u2.shadow_last_change == 14, "shadow_last_change should be 14")
    assert(u2.shadow_max == 15, "shadow_max should be 15")
    assert(u2.shadow_min == 16, "shadow_min should be 16")
    assert(u2.shadow_warning == 17, "shadow_warning should be 17")
    
    # Remove the Container now that we are done with it.
    @ad.remove_container @cn
    @ad.sync
  end
end
