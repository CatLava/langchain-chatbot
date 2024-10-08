# Experimental AWS AI chatbot
This is a Python based AI chatbot focused on AWS content. Under the hood, this is built with langchain and various tools components to ask questions on AWS infrastructure. The AI model used is Claude by Anthropic. For this chat bot to work, add valid API keys from the .env.example

## Running the bot

### Set your keys
Be sure to set your keys as per the .env.example file 

The bot can be run directly from cli with 
```python3 main.py```

Or via docker configuration with compose file, easy run with make command
```make run-interactive```


