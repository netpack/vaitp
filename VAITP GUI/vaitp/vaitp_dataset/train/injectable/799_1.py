import discord
from discord.ext import commands

# Create a bot instance with the required scopes
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.slash_command(name="example")
async def example_command(ctx):
    await ctx.respond("This is a safe command!")

# Run the bot with the proper token
bot.run('YOUR_TOKEN_HERE')