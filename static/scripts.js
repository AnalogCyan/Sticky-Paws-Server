/**
 * Loads levels by making a fetch request to "/levels" endpoint
 * and populates a level list in the DOM.
 *
 * @returns {Promise<void>} A promise that resolves when the levels are loaded and displayed.
 * @throws {Error} If the fetch request fails or an error occurs during the process.
 */
async function loadLevels() {
  fetch("/levels")
    .then((response) => {
      console.log("Fetch response:", response);

      if (!response.ok) {
        throw new Error(`Failed to fetch levels: ${response.statusText}`);
      }

      return response.json();
    })
    .then((levels) => {
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
    })
    .catch((error) => {
      console.error("Error fetching levels:", error);
    });
}

/**
 * Loads characters by making a fetch request to "/characters" endpoint
 * and populates a character list in the DOM.
 *
 * @returns {Promise<void>} A promise that resolves when the characters are loaded and displayed.
 * @throws {Error} If the fetch request fails or an error occurs during the process.
 */
function loadCharacters() {
  fetch("/characters")
    .then((response) => {
      console.log("Fetch response:", response);

      if (!response.ok) {
        throw new Error(`Failed to fetch characters: ${response.statusText}`);
      }

      return response.json();
    })
    .then((characters) => {
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
    })
    .catch((error) => {
      console.error("Error fetching characters:", error);
    });
}

// Load levels and characters initially
loadLevels();
loadCharacters();

// Refresh levels and characters every 10 seconds
setInterval(() => {
  loadLevels();
  loadCharacters();
}, 30000);
