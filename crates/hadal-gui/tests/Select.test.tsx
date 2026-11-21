import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Select, type SelectOption } from "../src/components/Select";

const REGION_OPTIONS: SelectOption[] = [
  { value: "eu-de", label: "Europe · Germany (Frankfurt)", group: "Europe" },
  { value: "eu-fr", label: "Europe · France (Paris)", group: "Europe" },
  { value: "na-va", label: "NA-East · Virginia", group: "North America" },
];

describe("Select dropdown anchoring, selection, outside-click & Escape layering", () => {
  afterEach(() => {
    cleanup();
  });

  it("opens, renders grouped options, selects an item, and closes drawer", async () => {
    const onChange = vi.fn();
    const { container } = render(() => {
      const [val, setVal] = createSignal("eu-de");
      return (
        <div class="select-row-scope">
          <Select
            value={val()}
            options={REGION_OPTIONS}
            onChange={(next) => {
              onChange(next);
              setVal(next);
            }}
          />
        </div>
      );
    });

    const trigger = container.querySelector(".select-trigger") as HTMLButtonElement;
    const drawer = container.querySelector(".select-drawer") as HTMLElement;

    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(trigger).toHaveTextContent("Europe · Germany (Frankfurt)");
    expect(drawer).toHaveAttribute("data-open", "false");
    expect(container.querySelector(".select-row-scope .studio-select")).toBeInTheDocument();

    await fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(drawer).toHaveAttribute("data-open", "true");
    expect(screen.getByText("Europe")).toBeInTheDocument();
    expect(screen.getByText("North America")).toBeInTheDocument();

    const targetOpt = screen.getByRole("button", { name: "NA-East · Virginia" });
    expect(targetOpt).toHaveAttribute("data-selected", "false");
    await fireEvent.click(targetOpt);

    expect(onChange).toHaveBeenCalledWith("na-va");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(drawer).toHaveAttribute("data-open", "false");
    expect(trigger).toHaveTextContent("NA-East · Virginia");
  });

  it("closes on Escape and stops propagation so window-level Escape handlers do not fire", async () => {
    const windowEscape = vi.fn();
    window.addEventListener("keydown", windowEscape);

    try {
      const { container } = render(() => (
        <Select value="eu-de" options={REGION_OPTIONS} onChange={vi.fn()} />
      ));
      const trigger = container.querySelector(".select-trigger") as HTMLButtonElement;
      const drawer = container.querySelector(".select-drawer") as HTMLElement;

      await fireEvent.click(trigger);
      expect(drawer).toHaveAttribute("data-open", "true");

      // First Escape closes the Select drawer and must NOT bubble to windowEscape.
      await fireEvent.keyDown(window, { key: "Escape" });
      expect(drawer).toHaveAttribute("data-open", "false");
      expect(trigger).toHaveAttribute("aria-expanded", "false");
      expect(windowEscape).not.toHaveBeenCalled();

      // Second Escape (now that Select is closed) reaches windowEscape normally.
      await fireEvent.keyDown(window, { key: "Escape" });
      expect(windowEscape).toHaveBeenCalledTimes(1);
    } finally {
      window.removeEventListener("keydown", windowEscape);
    }
  });

  it("closes on pointerdown outside the select container, but stays open on inside pointerdown", async () => {
    const { container } = render(() => (
      <div>
        <div data-testid="outside">outside</div>
        <Select value="eu-de" options={REGION_OPTIONS} onChange={vi.fn()} />
      </div>
    ));

    const trigger = container.querySelector(".select-trigger") as HTMLButtonElement;
    const drawer = container.querySelector(".select-drawer") as HTMLElement;

    await fireEvent.click(trigger);
    expect(drawer).toHaveAttribute("data-open", "true");

    // Pointerdown on group header inside select container keeps dropdown open
    await fireEvent.pointerDown(screen.getByText("Europe"));
    expect(drawer).toHaveAttribute("data-open", "true");

    // Pointerdown outside closes it
    await fireEvent.pointerDown(screen.getByTestId("outside"));
    expect(drawer).toHaveAttribute("data-open", "false");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });
});
