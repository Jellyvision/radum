require 'test/unit'
require '../active-directory'

# This tests the Container class.
class TC_Container < Test::Unit::TestCase
  def setup
    @c1a = ActiveDirectory::Container.new("ou=People")
    @c1b = ActiveDirectory::Container.new("ou=people")
    @c2a = ActiveDirectory::Container.new("ou=Staff,ou=People")
    @c2b = ActiveDirectory::Container.new("ou=Staff, ou=People")
    @c3a = ActiveDirectory::Container.new("cn=Users")
  end
  
  def test_no_spaces
    assert(@c2b.name.split(/\s+/).length == 1, "Should be no spaces in name")
  end
  
  def test_equal
    assert(@c1a == @c1a, "Should be equal")
  end
  
  def test_equal_case_insensitive
    assert(@c1a == @c1b, "Case insensitive equality test failed")
  end
  
  def test_equal_spaces
    assert(@c2a == @c2b, "Should be equal with whitespace difference")
  end
  
  def test_not_equal
    assert(@c1a != @c3a, "Should not be equal")
  end
end
