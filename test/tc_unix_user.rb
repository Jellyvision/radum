require 'test/unit'
require '../lib/radum'

# This tests the User class.
class TC_UNIXUser < Test::Unit::TestCase
  def setup
    @ad1 = RADUM::AD.new :root => "dc=vmware,dc=local", :password => "test1"
    @ad2 = RADUM::AD.new :root => "dc=vmware,dc=com", :password => "test2"
    @c1_ad1 = RADUM::Container.new :name => "ou=People", :directory => @ad1
    @c2_ad2 = RADUM::Container.new :name => "ou=Staff,ou=People",
                                   :directory => @ad2
    @ug1_c1_ad1 = RADUM::UNIXGroup.new("staff", @c1_ad1, 1001)
    @ug2_c1_ad1 = RADUM::UNIXGroup.new("enable", @c1_ad1, 1002)
    @ug3_c2_ad2 = RADUM::UNIXGroup.new("enable", @c2_ad2, 1003)
    @g4_c1_ad1 = RADUM::Group.new("class", @c1_ad1)
    @uu1a_c1_ad1 = RADUM::UNIXUser.new("user", @c1_ad1, @g4_c1_ad1, 1000,
                                        @ug1_c1_ad1, "/bin/bash", "/home/user")
  end
  
  def test_removed_flag_false
    assert(@uu1a_c1_ad1.removed == false, "Removed flag should be false")
  end
  
  def test_duplicate_uid_exception
    assert_raise RuntimeError do
      RADUM::UNIXUser.new("test", @c1_ad1, @g4_c1_ad1, 1000, @ug1_c1_ad1,
                          "/bin/bash", "/home/user")
    end
  end
  
  def test_unix_main_group_different_directory_exception
    assert_raise RuntimeError do
      RADUM::UNIXUser.new("test", @c1_ad1, @g4_c1_ad1, 1000, @ug3_c2_ad2,
                          "/bin/bash", "/home/test")
    end
  end
  
  def test_unix_main_group_non_unix_exception
    assert_raise RuntimeError do
      RADUM::UNIXUser.new("test", @c1_ad1, @g4_c1_ad1, 1000, @g4_c1_ad1,
                          "/bin/bash", "/home/test")
    end
  end
  
  def test_add_unix_group_different_directory_exception
    assert_raise RuntimeError do
      @uu1a_c1_ad1.add_group @ug3_c2_ad2
    end
  end
  
  def test_add_unix_group_no_exception
    assert_nothing_raised do
      @uu1a_c1_ad1.add_group @ug2_c1_ad1
    end
  end
  
  def test_add_group
    assert_block("Should have added exactly one group") do
      # Note that the UNIXUser already added its unix_main_group, so the count
      # should be two (so it should have really added a total of two groups
      # only).
      @uu1a_c1_ad1.add_group @ug2_c1_ad1
      @uu1a_c1_ad1.add_group @ug2_c1_ad1
      @uu1a_c1_ad1.groups.length == 2 &&
      @uu1a_c1_ad1.groups.find { |group| group == @ug2_c1_ad1 }
    end
  end
  
  def test_remove_unix_main_group_exception
    assert_raise RuntimeError do
      @uu1a_c1_ad1.remove_group @ug1_c1_ad1
    end
  end
end
