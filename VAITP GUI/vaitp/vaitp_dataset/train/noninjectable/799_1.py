import discord
from discord.ext import commands

# Create a bot instance with only application.commands scope (vulnerable)
bot = commands.Bot(command_prefix='!', intents=discord.Intents.default())

@bot.slash_command()
async def shutdown(ctx):
    # Vulnerable command that could be exploited to shut down the bot
    await ctx.respond("Shutting down...")
    await bot.close()

# Run the bot with the proper token
bot.run('YOUR_TOKEN_HERE')