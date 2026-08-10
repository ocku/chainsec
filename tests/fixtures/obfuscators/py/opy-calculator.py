# coding: UTF-8
import sys
l1l_opy_ = sys.version_info [0] == 2
l1l1l_opy_ = 2048
l111l_opy_ = 7
def ll_opy_ (l11_opy_):
    global l1l11_opy_
    l1111_opy_ = ord (l11_opy_ [-1])
    l1_opy_ = l11_opy_ [:-1]
    l1ll_opy_ = l1111_opy_ % len (l1_opy_)
    l1llll_opy_ = l1_opy_ [:l1ll_opy_] + l1_opy_ [l1ll_opy_:]
    if l1l_opy_:
        l111_opy_ = l11ll_opy_ () .join ([l1lll1_opy_ (ord (char) - l1l1l_opy_ - (l1lll_opy_ + l1111_opy_) % l111l_opy_) for l1lll_opy_, char in enumerate (l1llll_opy_)])
    else:
        l111_opy_ = str () .join ([chr (ord (char) - l1l1l_opy_ - (l1lll_opy_ + l1111_opy_) % l111l_opy_) for l1lll_opy_, char in enumerate (l1llll_opy_)])
    return eval (l111_opy_)
class l11l1_opy_:
    @staticmethod
    def add(a, b):
        return a + b
    @staticmethod
    def subtract(a, b):
        return a - b
    @staticmethod
    def l1l1_opy_(a, b):
        return a * b
    @staticmethod
    def l11l_opy_(a, b):
        return a / b if b != 0 else ll_opy_ (u"ࠦࡊࡸࡲࡰࡴࠥࠀ")
print(ll_opy_ (u"ࠧ࠷࠰ࠡ࠭ࠣ࠹ࠥࡃࠢࠁ"), l11l1_opy_.add(10, 5))
print(ll_opy_ (u"ࠨ࠱࠱ࠢ࠰ࠤ࠺ࠦ࠽ࠣࠂ"), l11l1_opy_.subtract(10, 5))
print(ll_opy_ (u"ࠢ࠲࠲ࠣ࠮ࠥ࠻ࠠ࠾ࠤࠃ"), l11l1_opy_.l1l1_opy_(10, 5))
print(ll_opy_ (u"ࠣ࠳࠳ࠤ࠴ࠦ࠵ࠡ࠿ࠥࠄ"), l11l1_opy_.l11l_opy_(10, 5))