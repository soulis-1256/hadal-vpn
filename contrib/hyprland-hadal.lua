-- Hyprland 0.55+/0.57+ Lua rules for Hadal VPN tray popover
-- Note: hadal-gui also installs these dynamically via `hyprctl eval` on launch.

hl.window_rule({
	name = "hadal-vpn-popover",
	match = { class = "^(hadal-gui|Hadal-gui|com\\.hadalvpn\\.app)$" },
	float = true,
	pin = true,
	border_size = 0,
	rounding = 8,
	opaque = true,
	no_blur = true,
	tag = "+nobar",
	["hyprbars:no_bar"] = true,
	size = { 360, 540 },
})
