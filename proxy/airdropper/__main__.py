from . import AirdropperApp

if __name__ == '__main__':
    airdropper_app = AirdropperApp()
    exit_code = airdropper_app.run()
    exit(exit_code)
