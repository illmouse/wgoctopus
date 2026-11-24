"""Run the Telegram bot."""
import logging

from .config import Config
from .handlers import build_application


def main() -> None:
    config = Config.from_env()
    logging.basicConfig(level=config.bot_log_level)
    build_application(config).run_polling(allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    main()
