#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define MAX_ENTITY 256

typedef struct animal {
    char name[32];
    char type[40];
    void (*unique_ability)(char *);
} Animal;

typedef struct plant {
    char type[20];
    char description[60];
} Plant;

typedef struct node {
    void * entity;
    unsigned type;
    struct node * next;
    struct node * prev;
} Node;

Node * tracking_root;
void * root_bucket[MAX_ENTITY];

void print_picture(char * object) {
    fflush(0);
    if (!strcmp("tree", object)) {
        system("cat ./tree.txt");
    } else if (!strcmp("cat", object)) {
        system("cat ./cat.txt");
    } else if (!strcmp("dog", object)) {
        system("cat ./dog.txt");
    } else if (!strcmp("deer", object)) {
        system("cat ./deer.txt");
    } else {
        printf("Sorry, no graphics for that object\n");
    }

    fflush(0);
}


void print_menu()
{
    printf("1. Create an Animal\n");
    printf("2. Create a Plant\n");
    printf("3. Run Simulation\n");
    printf("4. Remove Entity from Simulation\n");
    fflush(0);
}

void bark(char * name) {
    printf("%s, the dog, barks!\n", name);
    printf("Bark!\n");
    fflush(0);
};

void meow(char * name) {
    printf("%s, the cat, meows!\n", name);
    printf("meow\n");
    fflush(0);
}

void add_to_tracking(void * st, unsigned is_animal) {

    Node * new = (Node *)malloc(sizeof(Node));
    memset(new, 0, sizeof(Node));
    new->entity = st;
    new->type = is_animal;

    Node * walker = tracking_root;
    while(walker->next != NULL) {
        walker = walker->next;
    }

    new->prev = walker;
    walker->next = new;
}

void add_to_bucket(void * st) {
    unsigned int i = 0;
    while(root_bucket[i] != NULL && i < MAX_ENTITY) {
        i = i + 1;
    }

    if (i >= MAX_ENTITY) {
        printf("ERROR TOO MANY ENTITIES IN SIMULATION!\n");
        exit(-1);
    }

    root_bucket[i] = st;
    printf("[+] Tracking New Entity: Entity ID: %d\n", i);
}

void create_new_animal()
{
    Animal * new_animal = (Animal *)malloc(sizeof(Animal));
    memset(new_animal, 0, sizeof(Animal));

    printf("What kind of animal is this?\n");
    fflush(0);
    fgets(new_animal->type, 16, stdin);

    printf("What is this animal's name?\n");
    fflush(0);
    fgets(new_animal->name, 16, stdin);

    // Remove newline
    new_animal->type[strcspn(new_animal->type, "\n")] = 0;
    new_animal->name[strcspn(new_animal->name, "\n")] = 0;

    if (!strcmp(new_animal->type, "dog")) {
        new_animal->unique_ability = bark;
    } else if (!strcmp(new_animal->type, "cat")) {
        new_animal->unique_ability = meow;
    }

    // Add to global tracking methods
    add_to_tracking(new_animal, 1);
    add_to_bucket(new_animal);
}

void create_new_plant() {
    Plant * new_plant = (Plant *)malloc(sizeof(Plant));
    memset(new_plant, 0, sizeof(Plant));

    printf("What kind of plant is this\n");
    fflush(0);

    fgets(new_plant->type, 16, stdin);

    printf("Give a description of the plant\n");
    fflush(0);
    fgets(new_plant->description, 64, stdin);

    new_plant->type[strcspn(new_plant->type, "\n")] = 0;

    add_to_tracking(new_plant, 0);
    add_to_bucket(new_plant);
}

void run_simulation() {

    // root node is just a placeholder
    Node * walker = tracking_root->next;
    while(walker != NULL) {

        if ( walker->type  == 1) {
            Animal * target = (Animal *)walker->entity;

            printf("---------------------------------\n");
            printf("This is %s, a %s\n", target->name, target->type);
            fflush(0);

            if (target->unique_ability != NULL) {
                target->unique_ability(target->name);
            }
		    print_picture(target->type);
            printf("---------------------------------\n");
            fflush(0);


        } else {
            Plant * target = (Plant *)walker->entity;
            printf("---------------------------------\n");
            printf("This plant is a %s\n", target->type);
            printf("More information: %s\n", target->description);
		    print_picture(target->type);
            printf("---------------------------------\n");
            fflush(0);
        }

        walker = walker->next;
    }

    return;
}

void remove_entity() {
    printf("Which entity do you want to remove?\n");
    unsigned num = get_uint();

    if (num >= MAX_ENTITY) {
        printf("Invalid\n");
        return;
    }

    if (root_bucket[num] == NULL) {
        printf("Invalid\n");
        return;
    }

    free(root_bucket[num]);
}

int main()
{
    tracking_root = (Node *)malloc(sizeof(Node *));
    printf("Welcome to nature simulator 2.0\n");
    if (sizeof(Animal) != sizeof(Plant)) {
        printf("SIZE MISMATCH\n");
        printf("Animal: %d Plant: %d\n", sizeof(Animal), sizeof(Plant));
        return -1;
    }

    int looping = 1;
    while (looping)
    {
        print_menu();
        unsigned int choice = get_uint();

        switch(choice)
        {
            case 1:
                create_new_animal();
                break;

            case 2:
                create_new_plant();
                break;

            case 3:
                run_simulation();
                break;

            case 4:
                remove_entity();
                break;

            default:
                printf("ERROR: Invalid Option\n");
                looping = 0;
                break;
        }

    }

    return 0;
}
