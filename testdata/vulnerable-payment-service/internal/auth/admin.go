package auth

const AdminPassword = "admin123"

func CheckAdmin(input string) bool {
	return input == AdminPassword
}
