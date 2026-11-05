import unittest

from wechat_mcp.chatlog import render_content
from wechat_mcp.export import _one_line


class RenderContentTests(unittest.TestCase):
    def test_plain_text(self):
        self.assertEqual(render_content(1, 0, "  hello  "), "hello")

    def test_simple_types(self):
        self.assertEqual(render_content(3, 0, ""), "[图片]")
        self.assertEqual(render_content(34, 0, ""), "[语音]")
        self.assertEqual(render_content(47, 0, ""), "[表情]")
        self.assertEqual(render_content(43, 0, ""), "[视频]")

    def test_app_message(self):
        raw = "<msg><appmsg><type>57</type><title>分享标题</title></appmsg></msg>"
        self.assertEqual(render_content(49, 0, raw), "[分享] 分享标题")
        raw = "<msg><appmsg><type>2000</type><title>转账</title></appmsg></msg>"
        self.assertEqual(render_content(49, 0, raw), "[转账] 转账")
        raw = "<msg><appmsg><type>5</type><title>链接标题</title></appmsg></msg>"
        self.assertEqual(render_content(49, 0, raw), "[链接] 链接标题")

    def test_app_message_tolerates_namespaces(self):
        raw = (
            '<msg><appmsg appid="" sdkver="0"><title>文件.txt</title>'
            "<type>6</type></appmsg></msg>"
        )
        self.assertEqual(render_content(49, 0, raw), "[文件] 文件.txt")

    def test_system_message(self):
        self.assertEqual(
            render_content(10000, 0, "张三撤回了一条消息 0"),
            "张三撤回了一条消息",
        )
        self.assertEqual(
            render_content(10002, 0, '<sysmsg type="revokemsg">"李四" 撤回了一条消息</sysmsg>'),
            '"李四" 撤回了一条消息',
        )

    def test_unknown_type_falls_back_to_raw_text(self):
        self.assertEqual(render_content(999, 0, "raw text"), "raw text")
        self.assertEqual(render_content(999, 0, ""), "[类型999]")


class OneLineTests(unittest.TestCase):
    def test_collapses_newlines_and_blank_lines(self):
        self.assertEqual(_one_line("a\nb\r\n\r\n  c  "), "a / b / c")

    def test_strips_each_line(self):
        self.assertEqual(_one_line("  first  \n\tsecond\t"), "first / second")


if __name__ == "__main__":
    unittest.main()
