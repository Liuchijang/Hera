Change with your own API_KEY

pip install -r requirements.txt 

uvicorn main:app --reload 

Listening in http://127.0.0.1:8000/check_ip/{IP_TO_CHECK}
             http://127.0.0.1:8000/check_hash/{HASH_TO_CHECK}
