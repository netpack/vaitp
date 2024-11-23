from nonebot import MessageTemplate

# User-provided input that could potentially leak information
user_input = "User 's secret: ${SECRET_ENV_VAR}"

# Directly using user input in MessageTemplate without any filtering
template = MessageTemplate("Here is your message: {message}")
message = template.render(message=user_input)

print(message)