from typing import Tuple, Union, Deque
from core import expemu
from core import keys
from collections import deque
import os
import threading
import argparse
os.environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1"
import pygame

CWD = os.path.abspath(os.getcwd())
ROOTFS = os.path.join(CWD, "rootfs")

BLACK = pygame.Color(0, 0, 0)

EMU_PYG_KEY_MAP = {
    keys.KEY_ON:       pygame.K_ESCAPE,
    keys.KEY_ENTER:    pygame.K_RETURN,
    keys.KEY_UP:       pygame.K_UP,
    keys.KEY_DOWN:     pygame.K_DOWN,
    keys.KEY_LEFT:     pygame.K_LEFT,
    keys.KEY_RIGHT:    pygame.K_RIGHT,
    keys.KEY_F1:       pygame.K_F1,
    keys.KEY_F2:       pygame.K_F2,
    keys.KEY_F3:       pygame.K_F3,
    keys.KEY_F4:       pygame.K_F4,
    keys.KEY_F5:       pygame.K_F5,
    keys.KEY_F6:       pygame.K_F6,
    keys.KEY_SYMB:     pygame.K_1,
    keys.KEY_PLOT:     pygame.K_2,
    keys.KEY_NUM:      pygame.K_3,
    keys.KEY_HOME:     pygame.K_q,
    keys.KEY_APPS:     pygame.K_w,
    keys.KEY_VIEWS:    pygame.K_e,
    keys.KEY_0:        pygame.K_KP_0,
    keys.KEY_1:        pygame.K_KP_1,
    keys.KEY_2:        pygame.K_KP_2,
    keys.KEY_3:        pygame.K_KP_3,
    keys.KEY_4:        pygame.K_KP_4,
    keys.KEY_5:        pygame.K_KP_5,
    keys.KEY_6:        pygame.K_KP_6,
    keys.KEY_7:        pygame.K_KP_7,
    keys.KEY_8:        pygame.K_KP_8,
    keys.KEY_9:        pygame.K_KP_9,
    keys.KEY_PLUS:     pygame.K_KP_PLUS,
    keys.KEY_SUBTRACTION: pygame.K_KP_MINUS,
    keys.KEY_MULTIPLICATION: pygame.K_KP_MULTIPLY,
    keys.KEY_DIVISION: pygame.K_KP_DIVIDE,
    keys.KEY_DOT:      pygame.K_KP_PERIOD,
    keys.KEY_LEFTBRACKET: pygame.K_LEFTBRACKET,
    keys.KEY_RIGHTBRACET: pygame.K_RIGHTBRACKET,
    keys.KEY_BACKSPACE: pygame.K_BACKSPACE,
    keys.KEY_SHIFT:    pygame.K_LSHIFT,
    keys.KEY_ALPHA:    pygame.K_CAPSLOCK,
}

PYG_EMU_KEY_MAP = {v:k for k, v in EMU_PYG_KEY_MAP.items()}

class PYGameUIInterface(expemu.UIInterface):
    def __init__(self, screen: pygame.Surface):
        self.screen = screen
        # in memory surface, to speed up drawing
        self.surface = pygame.Surface((expemu.EMU_SCREEN_WIDTH, expemu.EMU_SCREEN_HEIGHT), depth=8)
        self.color_map = []
        for color in range(256):
            self.color_map.append(pygame.Color(color, color, color))
        self.key_event_queue: Deque[Tuple[bool, int]] = deque()

    def fill_rect(self, x, y, w, h, c):
        self.surface.fill(
            self.color_map[c & 0xFF],
            (x, y, w, h)
        )
    
    def draw_text(self, text, x, y, bg, fg):
        print(f"Drawing '{text}' at {x}, {y} with color bg {bg}, fg {fg}.")
    
    def is_key_down(self, key_id) -> bool:
        if key_id in EMU_PYG_KEY_MAP:
            return pygame.key.get_pressed()[EMU_PYG_KEY_MAP[key_id]]
        return False
    
    def query_key_event(self) -> Union[None, Tuple[bool, int]]:
        if len(self.key_event_queue) <= 0:
            return None
        else:
            return self.key_event_queue.popleft()
    
    def _push_key_event(self, pressed: bool, key_id: int):
        self.key_event_queue.append((pressed, key_id))
    
    def _render_on_screen(self):
        self.screen.blit(
            pygame.transform.scale(
                self.surface,
                (self.screen.get_width(), self.screen.get_height())
            ),
            (0, 0, self.screen.get_width(), self.screen.get_height())
        )
        pygame.display.flip()

def mainloop():
    # parse args from cli
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "exp",
        metavar="<ExistOS Program Path>",
        help="ExistOS program file path (*.exp)",
    )
    parser.add_argument(
        "-s", "--scale",
        default=2,
        type=int,
        metavar="Scale",
        help="Screen scale factor",
    )
    args = parser.parse_args()
    if not args.exp.lower().endswith(".exp"):
        print("Error: file should be *.exp")
        return
    # init pygame
    pygame.init()
    pygame.display.set_caption("EXP Emulator")
    # init screen
    screen = pygame.display.set_mode(
        (expemu.EMU_SCREEN_WIDTH * args.scale, expemu.EMU_SCREEN_HEIGHT * args.scale),
        vsync=True
    )
    screen.fill(BLACK)
    pygame.display.flip()
    # init GUI interface
    gui = PYGameUIInterface(screen)
    # init rootfs
    os.makedirs(ROOTFS, exist_ok=True)
    # init emu
    emu = expemu.Emulator(gui, ROOTFS, args.exp)
    # init pygame clock
    clock = pygame.time.Clock()
    # running
    emu_thead = threading.Thread(target=emu.emu_thread, daemon=True)
    emu_thead.start()
    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
                pygame.quit()
                return
            elif event.type == pygame.KEYDOWN:
                if event.key in PYG_EMU_KEY_MAP:
                    gui._push_key_event(True, PYG_EMU_KEY_MAP[event.key])
            elif event.type == pygame.KEYUP:
                if event.key in PYG_EMU_KEY_MAP:
                    gui._push_key_event(False, PYG_EMU_KEY_MAP[event.key])
        # render screen
        gui._render_on_screen()
        clock.tick(60.0)

if __name__ == "__main__":
    try:
        mainloop()
    except KeyboardInterrupt:
        pass
