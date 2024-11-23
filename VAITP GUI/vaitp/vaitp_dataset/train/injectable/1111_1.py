from nonebot import MessageTemplate

# User-provided input that could potentially leak information
user_input = "User 's secret: ${SECRET_ENV_VAR}"

# Temporary workaround: filter underscores before incorporating user input
safe_input = user_input.replace("_", "")

# Using MessageTemplate with filtered user input
template = MessageTemplate("Here is your message: {message}")
message = template.render(message=safe_input)

print(message)