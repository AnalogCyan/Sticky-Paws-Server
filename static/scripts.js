async function loadLevels() {
  try {
    const response = await fetch("/levels");
    console.log("Fetch response:", response);

    if (!response.ok) {
      throw new Error(`Failed to fetch levels: ${response.statusText}`);
    }

    const levels = await response.json();
    console.log("Fetched levels:", levels);
    const levelList = document.getElementById("level-list");

    // Clear the existing list items
    while (levelList.firstChild) {
      levelList.removeChild(levelList.firstChild);
    }

    // Add the fetched levels to the list
    for (const level of levels) {
      const listItem = document.createElement("li");
      listItem.textContent = level.name.replace("levels/", "");
      levelList.appendChild(listItem);
    }
  } catch (error) {
    console.error("Error fetching levels:", error);
    alert(`Error fetching levels: ${error.message}`);
  }
}

// Load levels initially
loadLevels();

// Refresh levels every 10 seconds
setInterval(loadLevels, 10000);
