import discord
from discord.ext import commands

# Create a bot instance with only application.commands scope (vulnerable)
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.slash_command(name="shutdown", description="Shuts down the bot.")
async def shutdown(ctx):
    # Vulnerable command that could be exploited to shut down the bot
    await ctx.respond("Shutting down...")
    await bot.close()

# Run the bot with the proper token
bot.run('YOUR_TOKEN_HERE')