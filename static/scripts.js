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
      listItem.textContent = `${level.name.replace(
        "levels/",
        ""
      )} - Uploaded: ${level.time_created}`;
      levelList.appendChild(listItem);
    }
  } catch (error) {
    console.error("Error fetching levels:", error);
  }
}

async function loadCharacters() {
  try {
    const response = await fetch("/characters");
    console.log("Fetch response:", response);

    if (!response.ok) {
      throw new Error(`Failed to fetch characters: ${response.statusText}`);
    }

    const characters = await response.json();
    console.log("Fetched characters:", characters);
    const characterList = document.getElementById("character-list");

    // Clear the existing list items
    while (characterList.firstChild) {
      characterList.removeChild(characterList.firstChild);
    }

    // Add the fetched characters to the list
    for (const character of characters) {
      const listItem = document.createElement("li");
      listItem.textContent = `${character.name.replace(
        "characters/",
        ""
      )} - Uploaded: ${character.time_created}`;
      characterList.appendChild(listItem);
    }
  } catch (error) {
    console.error("Error fetching characters:", error);
  }
}

// Load levels and characters initially
loadLevels();
loadCharacters();

// Refresh levels and characters every 10 seconds
setInterval(() => {
  loadLevels();
  loadCharacters();
}, 10000);
