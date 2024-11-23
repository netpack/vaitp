from botbuilder.core import ActivityHandler, TurnContext

class MyBot(ActivityHandler):
    async def on_message_activity(self, turn_context: TurnContext):
        # Process the incoming message
        user_message = turn_context.activity.text

        # Potentially disclosing sensitive information
        response_message = f"You said: {user_message}. Here's some sensitive info: {turn_context.activity}."
        
        # Send the response
        await turn_context.send_activity(response_message)

    async def on_turn(self, turn_context: TurnContext):
        if turn_context.activity.type == "message":
            await self.on_message_activity(turn_context)
        else:
            # Handle other types of activities
            pass