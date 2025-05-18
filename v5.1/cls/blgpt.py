from datetime import datetime
import random
import psutil
import openai


class GPT:


    def CmdList(self):
        return list(filter(lambda x: x[:2]!='__', dir(self)))

    def writehello(self):
        return "hello world"


    def SendMessageToChatGPT(self, UserId, message: str) -> str:
        """
        Sends a message to ChatGPT and returns the response.

        Args:
            user_id (int): The ID of the user making the request.
            message (str): The message to send to ChatGPT.

        Returns:
            str: The response from ChatGPT.
        """
        print("I AM HERE")
        # Retrieve API key from the environment or configuration
        api_key = "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"
        if not api_key:
            raise ValueError("OpenAI API key is not configured.")

        openai.api_key = api_key

        # Log the message sent for auditing purposes (optional)
        print(f"User sent message: {message}")

        try:
            response = openai.chat.completions.create(
                model="gpt-3.5-turbo",
                store=True,
                messages=[
                    {"role": "user", "content": message},
                ]
            )

            # Extract the assistant's response
            chat_response = response.choices[0].message.content

            # Optionally log or store the response (e.g., in the database)
            print(f"ChatGPT response for User: {chat_response}")

            return chat_response
        except Exception as e:
            print(f"Error communicating with ChatGPT: {e}")
            return "An error occurred while processing your request. Please try again later."
