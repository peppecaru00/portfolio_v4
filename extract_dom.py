from bs4 import BeautifulSoup

with open('scratch_detail.html', 'r', encoding='utf-8') as f:
    soup = BeautifulSoup(f.read(), 'html.parser')

main = soup.find(id='main-content')
if main:
    with open('detail_dom.txt', 'w', encoding='utf-8') as out:
        out.write(str(main))
