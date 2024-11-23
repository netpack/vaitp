from botbuilder.core import ActivityHandler, TurnContext
from botbuilder.schema import Activity, ActivityTypes

class MyBot(ActivityHandler):
    async def on_message_activity(self, turn_context: TurnContext):
        # Process the incoming message
        user_message = turn_context.activity.text

        # Respond without disclosing sensitive information
        response_message = "Thank you for your message!"
        
        # Send the response
        await turn_context.send_activity(Activity(type=ActivityTypes.message, text=response_message))

    async def on_turn(self, turn_context: TurnContext):
        # Ensure we handle only the necessary activities
        if turn_context.activity.type == ActivityTypes.message:
            await self.on_message_activity(turn_context)
        else:
            # Handle other types of activities if needed
            pass