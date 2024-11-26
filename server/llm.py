import requests
import json


token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImU4ZWUxMjg3LWU3YTItNDEwOC05ZGJkLThkOGI2MGJmODMzOCJ9.-hZ7QuNmEs1kit_8SOlu8bvTy97OtUYrpC8NOmY5XsA"

def get_completion(prompt):
    return "I don't want to pay for openai credits at the moment"
    # url = 'http://10.0.0.93:3000/api/chat/completions'
    # headers = {
    #     'Authorization': f'Bearer {token}',
    #     'Accept': 'application/json'
    # }
    # payload = {
    #     'model': 'llama3.2:latest',
    #     'messages':
    #         [
    #             {
    #                 'role': 'system',
    #                 'content': 'You are a helpful assistant.'
    #             },
    #             {
    #                 'role': 'user',
    #                 'content': prompt
    #             }
    #         ]
    # }
    # response = requests.post(url, headers=headers, json=payload)

    # response = json.loads(response.text)
    # return response['choices'][0]['message']['content']
