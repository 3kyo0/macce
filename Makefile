CC      ?= clang
CXX     ?= clang++
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -g -Ilib
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17 -g -Ilib

# --- library ---
LIB_SRCS := lib/memreader.c lib/scanner.c
LIB_OBJS := $(LIB_SRCS:.c=.o)
LIB      := libmacce.a

# --- CLI ---
CLI_SRCS := cli/cli_main.c
CLI_OBJS := $(CLI_SRCS:.c=.o)
CLI      := macce

# --- GUI (ImGui + GLFW) ---
GLFW_PREFIX := $(shell brew --prefix glfw 2>/dev/null)
IMGUI_DIR   := gui/third_party/imgui

GUI_CXX_SRCS := \
    gui/gui_main.cpp \
    gui/app.cpp \
    $(IMGUI_DIR)/imgui.cpp \
    $(IMGUI_DIR)/imgui_draw.cpp \
    $(IMGUI_DIR)/imgui_tables.cpp \
    $(IMGUI_DIR)/imgui_widgets.cpp \
    $(IMGUI_DIR)/backends/imgui_impl_glfw.cpp \
    $(IMGUI_DIR)/backends/imgui_impl_opengl2.cpp
GUI_OBJS := $(GUI_CXX_SRCS:.cpp=.o)
GUI      := macce-gui

GUI_CXXFLAGS := $(CXXFLAGS) \
    -I$(IMGUI_DIR) -I$(IMGUI_DIR)/backends \
    -I$(GLFW_PREFIX)/include \
    -Wno-unused-parameter
GUI_LDFLAGS  := \
    -L$(GLFW_PREFIX)/lib -lglfw \
    -framework Cocoa -framework IOKit -framework OpenGL

ENT := entitlements.plist

all: $(CLI)

# --- library rules ---
$(LIB): $(LIB_OBJS)
	ar rcs $@ $(LIB_OBJS)

lib/%.o: lib/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# --- CLI rules ---
cli/%.o: cli/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(CLI): $(CLI_OBJS) $(LIB)
	$(CC) $(CFLAGS) $(CLI_OBJS) $(LIB) -o $@
	codesign --force --sign - --entitlements $(ENT) $@

# --- GUI rules ---
$(IMGUI_DIR)/imgui.cpp:
	@echo "==> ImGui not vendored. Run 'make imgui' first."
	@exit 1

imgui:
	@mkdir -p gui/third_party
	@if [ ! -d $(IMGUI_DIR) ]; then \
	    git clone --depth 1 --branch v1.91.5 \
	        https://github.com/ocornut/imgui.git $(IMGUI_DIR); \
	fi
	@echo "ImGui ready at $(IMGUI_DIR)"

gui/%.o: gui/%.cpp
	$(CXX) $(GUI_CXXFLAGS) -c $< -o $@

$(IMGUI_DIR)/%.o: $(IMGUI_DIR)/%.cpp
	$(CXX) $(GUI_CXXFLAGS) -c $< -o $@

$(IMGUI_DIR)/backends/%.o: $(IMGUI_DIR)/backends/%.cpp
	$(CXX) $(GUI_CXXFLAGS) -c $< -o $@

gui: $(GUI)

$(GUI): $(GUI_OBJS) $(LIB)
	$(CXX) $(GUI_CXXFLAGS) $(GUI_OBJS) $(LIB) $(GUI_LDFLAGS) -o $@
	codesign --force --sign - --entitlements $(ENT) $@

# --- clean ---
clean:
	rm -rf $(LIB) $(CLI) $(GUI) $(CLI).dSYM $(GUI).dSYM
	find lib cli gui -name '*.o' -delete 2>/dev/null || true

distclean: clean
	rm -rf $(IMGUI_DIR)

.PHONY: all gui imgui clean distclean
