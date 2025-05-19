import pyqrcode
from pyqrcode import QRCode # type: ignore

s ="09303968874"
url = pyqrcode.create(s)
url.svg("myqr glezy.svg", scale = 8)
url.png('Paymentglezy.png', scale =6)