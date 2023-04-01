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
    alert(`Error fetching characters: ${error.message}`);
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
