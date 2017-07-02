import os
import shutil

ROOT_DIR = '.awsm'
KEYS_PATH = 'keys.yml'
PROFILES_PATH = 'profiles.yml'
HOOKS_PATH = 'hooks.yml'

USER_CFG_DIR = os.path.expanduser(os.path.join('~', ROOT_DIR))
USER_KEYS_CFG = os.path.join(USER_CFG_DIR, KEYS_PATH)
USER_PROFILES_DIR = os.path.join(USER_CFG_DIR, 'profiles')
USER_HOOKS_DIR = os.path.join(USER_CFG_DIR, 'hooks')

PROJECT_CFG_DIR = os.path.join(os.getcwd(), ROOT_DIR)
PROJECT_IDENTITY = os.path.join(PROJECT_CFG_DIR, 'identifier')
PROJECT_TAGS = os.path.join(PROJECT_CFG_DIR, 'tags.yml')
PROJECT_PROFILES_CFG = os.path.join(os.getcwd(), PROFILES_PATH)
PROJECT_HOOKS_CFG = os.path.join(os.getcwd(), HOOKS_PATH)


##
## Run this when any of the above paths are imported
##
def _init_awsm_user_config():
    # Skip initialization if the user directory has already been initialized
    if os.path.exists(USER_CFG_DIR):
        return

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_root = os.path.join(base_dir, 'templates')

    # Make the root user directories, if necessary
    for d in (
            USER_CFG_DIR,
            USER_PROFILES_DIR,
            USER_HOOKS_DIR,
    ):
        os.makedirs(d, exist_ok=True)

    # Add the default config files
    for cfg, dest_dir in (
            (KEYS_PATH, None),
            (PROFILES_PATH, USER_PROFILES_DIR),
            (HOOKS_PATH, USER_HOOKS_DIR),
    ):
        dst = (
            os.path.join(USER_CFG_DIR, cfg)
            if dest_dir is None else
            os.path.join(dest_dir, 'main.yml')
        )

        if not os.path.exists(dst):
            src = os.path.join(templates_root, cfg)
            shutil.copyfile(src, dst)

_init_awsm_user_config()
