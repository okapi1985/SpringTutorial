package tacos;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import tacos.data.IngredientRepository;
import tacos.data.OrderRepository;
import tacos.data.TacoRepository;
import tacos.web.DesignTacoController;
import tacos.Ingredient.Type;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@WebMvcTest(DesignTacoController.class)
public class DesignTacoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    private List<Ingredient> ingredients;

    private Taco design;

    @MockBean
    private IngredientRepository ingredientRepository;

    @MockBean
    private TacoRepository designRepository;

    @MockBean
    private OrderRepository orderRepository;

    @Before
    public void setup(){
        ingredients = Arrays.asList(
                new Ingredient("FLTO", "pszenna", Type.WRAP),
                new Ingredient("COTO", "kukurydziana", Type.WRAP),
                new Ingredient("GRBF", "mielona wołowina", Type.PROTEIN),
                new Ingredient("CARN", "kawałki mięsa", Type.PROTEIN),
                new Ingredient("TMTO", "pomidory pokrojone w kostkę", Type.VEGGIES),
                new Ingredient("LETC", "sałata", Type.VEGGIES),
                new Ingredient("CHED", "cheddar", Type.CHEESE),
                new Ingredient("JACK", "Monterrey Jack", Type.CHEESE),
                new Ingredient("SLSA", "pikantny sos pomidorowy", Type.SAUCE),
                new Ingredient("SRCR", "śmietana", Type.SAUCE)
        );

        when(ingredientRepository.findAll()).thenReturn(ingredients);

        when(ingredientRepository.findById("FLTO")).thenReturn(Optional.of(new Ingredient("FLTO", "pszenna", Type.WRAP)));
        when(ingredientRepository.findById("GRBF")).thenReturn(Optional.of(new Ingredient("GRBF", "mielona wołowina", Type.PROTEIN)));
        when(ingredientRepository.findById("CHED")).thenReturn(Optional.of(new Ingredient("CHED", "cheddar", Type.CHEESE)));

        design = new Taco();
        design.setName("Test Taco");

        design.setIngredients(Arrays.asList(
                new Ingredient("FLTO", "pszenna", Type.WRAP),
                new Ingredient("GRBF", "mielona wołowina", Type.PROTEIN),
                new Ingredient("CHED", "cheddar", Type.CHEESE)
        ));
    }

    @Test
    public void testShowDesignForm() throws Exception{
        mockMvc.perform(get("/design"))
                .andExpect(status().isOk())
                .andExpect(view().name("design"))
                .andExpect(model().attribute("wrap", ingredients.subList(0,2)))
                .andExpect(model().attribute("protein", ingredients.subList(2, 4)))
                .andExpect(model().attribute("veggies", ingredients.subList(4, 6)))
                .andExpect(model().attribute("cheese", ingredients.subList(6, 8)))
                .andExpect(model().attribute("sauce", ingredients.subList(8, 10)));
    }

    @Test
    public void processDesign() throws Exception{
        when(designRepository.save(design))
                .thenReturn(design);

        mockMvc.perform(post("/design")
                .content("name=Test+Taco&ingredients=FLTO,GRBF,CHED")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().stringValues("Location", "/orders/current"));

    }
}