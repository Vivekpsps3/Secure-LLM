import requests
import json



def get_completion(prompt):
    url = 'http://localhost:11434/api/generate'
    payload = {
        'model': 'llama3.2',
        'prompt': prompt,
        "stream": False,
    }
    response = requests.post(url, json=payload)

    response = json.loads(response.text)
    return response["response"]

if __name__ == '__main__':
    prompt = "Hello, my name is"
    completion = get_completion(prompt)
    print(completion)