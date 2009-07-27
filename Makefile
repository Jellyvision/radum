doc:
	@rdoc --exclude test --exclude 'demo*' --exclude 'radum-gemspec.rb' --exclude 'lib/radum.rb' --main RADUM --accessor directory --title "RADUM -- Ruby Active Directory User Management" --line-numbers --inline-source --charset=UTF-8 LICENSE .

clean:
	@rm -rf doc
