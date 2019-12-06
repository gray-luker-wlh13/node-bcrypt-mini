INSERT INTO auth_user (user_email, user_password)
VALUES ($1, $2)
RETURNING *;
