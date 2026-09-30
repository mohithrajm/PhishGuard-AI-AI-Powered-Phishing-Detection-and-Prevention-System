# Server launcher for PhishGuard AI
import sys
import os
import uvicorn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'api'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'ml'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src', 'defense'))

if __name__ == '__main__':
    print('\n' + '='*65)
    print('  [+] PhishGuard AI - Cyber Threat Intelligence & Defense System')
    print('  [*] Web Console:  http://127.0.0.1:8000')
    print('  [*] API Docs:     http://127.0.0.1:8000/docs')
    print('='*65 + '\n')
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=False)
