doc:
	@rdoc --exclude test --exclude 'demo*' --exclude radum-gemspec.rb --exclude lib/radum.rb --exclude Makefile --exclude Notes.txt --main RADUM --title "RADUM -- Ruby Active Directory User Management" --line-numbers --inline-source --charset=UTF-8 LICENSE .

clean:
	@rm -rf doc
