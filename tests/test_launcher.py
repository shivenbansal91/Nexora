"""Stdlib checks: python -m unittest discover -s tests -p test_launcher.py"""
import unittest
from unittest.mock import Mock, patch

import start_nexora as launcher


class LauncherChecks(unittest.TestCase):
    def test_health_alone_cannot_identify_an_unrelated_service(self):
        with patch.object(launcher, 'get_json', side_effect=[{'name': 'another app'}]):
            self.assertFalse(launcher.is_ready())
        with patch.object(launcher, 'get_json', side_effect=[{'name': 'Nexora Security Monitoring API'}, {'status': 'ok'}]):
            self.assertTrue(launcher.is_ready())

    def test_existing_server_is_reused_without_starting_another(self):
        with patch.object(launcher, 'prepare_frontend'), patch.object(launcher, 'is_ready', return_value=True), patch.object(launcher.webbrowser, 'open') as browser, patch.object(launcher.subprocess, 'Popen') as spawn:
            self.assertEqual(launcher.main(), 0)
            spawn.assert_not_called()
            browser.assert_called_once_with(launcher.URL + '/dashboard')

    def test_startup_failure_does_not_open_browser(self):
        process = Mock()
        process.poll.return_value = 1
        with patch.object(launcher, 'is_ready', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'stopped during startup'):
                launcher.wait_until_ready(process)

    def test_waits_for_health_before_continuing(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(launcher, 'is_ready', side_effect=[False, True]), patch.object(launcher.time, 'sleep') as sleep:
            launcher.wait_until_ready(process)
            sleep.assert_called_once()

    def test_occupied_port_is_not_killed_or_reused(self):
        probe = Mock()
        probe.bind.side_effect = OSError('occupied')
        with patch.object(launcher, 'prepare_frontend'), patch.object(launcher, 'is_ready', return_value=False), patch.object(launcher.socket, 'socket') as socket, patch.object(launcher.subprocess, 'Popen') as spawn:
            socket.return_value.__enter__.return_value = probe
            self.assertEqual(launcher.main(), 1)
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
