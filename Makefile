doc:
	@rdoc --exclude test --main RADUM --accessor directory --title "Ruby Active Directory User Management"

clean:
	@rm -rf doc
