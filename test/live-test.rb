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
    
    puts "Conducting live test with the following settings:\n\n"
    puts "AD Root: #{@root}"
    puts "AD User: #{@user}"
    puts "AD Password: #{@password}"
    puts "AD Server: #{@server}"
    
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
    puts "Using Container: #{@cn.name}"
    puts
    puts "Don't forget to check the live-test.txt debug log file for errors."
    puts
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
  
  def test_user_attributes
    RADUM::logger.log("\ntest_user_attributes()", RADUM::LOG_DEBUG)
    RADUM::logger.log("----------------------", RADUM::LOG_DEBUG)
    u = RADUM::User.new :username => "win-user-" + $$.to_s, :container => @cn,
                        :primary_group => @domain_users
    
    # Test setting all attributes.
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
    
    # Test modifying all set attributes.
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
    # begin with when we've not employed this logic whatsoever.
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
    g = RADUM::Group.new :name => "win-group-" + $$.to_s, :container => @cn
    u.primary_group = g
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    du = ad2.find_group_by_name("Domain Users")
    g = ad2.find_group_by_name("win-group-" + $$.to_s)
    assert(u2.primary_group == g, "primary_group should be #{g}")
    u.primary_group = @domain_users
    @ad.sync
    ad2 = new_ad
    u2 = ad2.find_user_by_username "win-user-" + $$.to_s
    du = ad2.find_group_by_name("Domain Users")
    assert(u2.primary_group == du, "primary_group should be #{du}")
    
  end
end
